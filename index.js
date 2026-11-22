import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";

const app = express();
const port = Number(process.env.PORT) || 5000;

const requiredEnv = [
  "MONGODB_URI",
  "BETTER_AUTH_SECRET",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "IMGBB_KEY",
  "CLIENT_URL",
];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing required env: ${key}`);
  }
}

const stripeSecret = process.env.STRIPE_SECRET_KEY;
const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

const allowedOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
  })
);

app.use((err, req, res, next) => {
  if (err?.message === "Not allowed by CORS") {
    return res.status(403).json({ message: "CORS origin not allowed" });
  }
  return next(err);
});

const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error("MONGODB_URI is required");
  process.exit(1);
}

const client = new MongoClient(mongoUri);
let collections;

const VALID_ROLES = ["admin", "vendor", "customer"];
const SERVICE_STATUSES = ["pending", "approved", "rejected"];
const BOOKING_STATUSES = ["pending", "accepted", "rejected", "cancelled"];

function jsonError(res, status, message, details) {
  const body = { message };
  if (details !== undefined) body.details = details;
  return res.status(status).json(body);
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function getBearerToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || typeof authHeader !== "string") return null;
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7).trim();
  return token || null;
}

function isValidObjectId(id) {
  return typeof id === "string" && ObjectId.isValid(id) && new ObjectId(id).toString() === id;
}

function toObjectId(id) {
  return new ObjectId(id);
}

function asIdString(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  if (value instanceof ObjectId) return value.toString();
  if (typeof value === "object" && value.toString) return value.toString();
  return String(value);
}

function sameId(a, b) {
  return asIdString(a) === asIdString(b);
}

function isNonEmptyString(v, max = 500) {
  return typeof v === "string" && v.trim().length > 0 && v.trim().length <= max;
}

function parsePositiveNumber(v) {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function isValidDateString(v) {
  if (!isNonEmptyString(v, 100)) return false;
  const d = new Date(v);
  return !Number.isNaN(d.getTime());
}

function isPremiumActive(user) {
  if (user?.subscriptionPlan !== "premium") return false;
  if (!user?.subscriptionExpiresAt) return false;
  const expiry = new Date(user.subscriptionExpiresAt);
  return !Number.isNaN(expiry.getTime()) && expiry.getTime() > Date.now();
}

async function findUserById(id) {
  const idStr = asIdString(id);
  const queries = [];
  if (isValidObjectId(idStr)) queries.push({ _id: toObjectId(idStr) });
  queries.push({ _id: idStr });
  queries.push({ id: idStr });
  for (const q of queries) {
    const user = await collections.users.findOne(q);
    if (user) return user;
  }
  return null;
}

async function findSessionByToken(token) {
  const session = await collections.sessions.findOne({ token });
  if (session) return session;
  return collections.sessions.findOne({ sessionToken: token });
}

function isSessionExpired(session) {
  const exp = session?.expiresAt || session?.expires || session?.sessionExpiresAt;
  if (!exp) return false;
  const d = new Date(exp);
  return !Number.isNaN(d.getTime()) && d.getTime() <= Date.now();
}

const verifyToken = asyncHandler(async (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) return jsonError(res, 401, "Unauthorized: missing or invalid Bearer token");

  const session = await findSessionByToken(token);
  if (!session) return jsonError(res, 401, "Unauthorized: invalid session token");
  if (isSessionExpired(session)) return jsonError(res, 401, "Unauthorized: session expired");

  const user = await findUserById(session.userId);
  if (!user) return jsonError(res, 401, "Unauthorized: user not found");
  if (user.isBlocked) return jsonError(res, 403, "Forbidden: account is blocked");

  const role = user.role;
  if (!VALID_ROLES.includes(role)) return jsonError(res, 403, "Forbidden: invalid user role");

  req.user = user;
  req.authSession = session;
  return next();
});

const verifyRole = (roles) => (req, res, next) => {
  if (!req.user) return jsonError(res, 401, "Unauthorized");
  if (!roles.includes(req.user.role)) return jsonError(res, 403, "Forbidden: insufficient role");
  return next();
};

function ensureStripe(res) {
  if (!stripe) {
    jsonError(res, 500, "Stripe is not configured");
    return false;
  }
  return true;
}

function sanitizeService(doc) {
  return doc;
}

function sanitizeUser(user) {
  const { password, ...rest } = user || {};
  return rest;
}

async function connectDB() {
  await client.connect();
  const db = client.db(process.env.DB_NAME || "vowvista");
  collections = {
    users: db.collection("user"),
    sessions: db.collection("session"),
    services: db.collection("services"),
    bookings: db.collection("bookings"),
    transactions: db.collection("transactions"),
  };

  await collections.services.createIndex({ status: 1, isActive: 1, createdAt: -1 });
  await collections.bookings.createIndex({ serviceId: 1, eventDate: 1, status: 1 });
  await collections.transactions.createIndex({ stripeSessionId: 1 }, { unique: true, sparse: true });
  console.log("Connected to MongoDB");
}

// Stripe webhook must be before express.json
app.post("/payments/webhook", express.raw({ type: "application/json" }), asyncHandler(async (req, res) => {
  if (!ensureStripe(res)) return;
  const sig = req.headers["stripe-signature"];
  if (!sig || !process.env.STRIPE_WEBHOOK_SECRET) {
    return jsonError(res, 400, "Missing Stripe signature or webhook secret");
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return jsonError(res, 400, `Webhook signature verification failed: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    await fulfillSubscriptionSession(session, event.id);
  }

  return res.status(200).json({ received: true });
}));

async function fulfillSubscriptionSession(session, eventId) {
  const vendorId = session?.metadata?.vendorId;
  if (!isValidObjectId(vendorId)) return;

  const stripeSessionId = session.id;
  const existingTx = await collections.transactions.findOne({ stripeSessionId });
  if (!existingTx) {
    try {
      await collections.transactions.insertOne({
        vendorId,
        plan: "premium",
        amount: typeof session.amount_total === "number" ? session.amount_total / 100 : 0,
        currency: (session.currency || "usd").toUpperCase(),
        stripeSessionId,
        stripeSubscriptionId: session.subscription || null,
        stripeEventId: eventId || null,
        status: "success",
        createdAt: new Date(),
        immutable: true,
      });
    } catch (err) {
      if (!(err?.code === 11000)) throw err;
    }
  }

  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 30);

  const user = await findUserById(vendorId);
  if (!user) return;
  await collections.users.updateOne(
    { _id: user._id },
    {
      $set: {
        subscriptionPlan: "premium",
        subscriptionExpiresAt: expiryDate,
        premiumActivatedAt: new Date(),
        stripeCustomerId: session.customer || user.stripeCustomerId || null,
      },
    }
  );
}

app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  if (req.headers.origin && !allowedOrigins.includes(req.headers.origin)) {
    return jsonError(res, 403, "CORS origin not allowed");
  }
  return next();
});

app.get("/", (req, res) => res.json({ ok: true, message: "VowVista API is running" }));
// SERVICES
app.get("/services", asyncHandler(async (req, res) => {
  const { search, category, location, sort } = req.query;
  const query = { status: "approved", isActive: true };

  if (search !== undefined) {
    if (!isNonEmptyString(search, 100)) return jsonError(res, 400, "Invalid search query");
    query.serviceName = { $regex: search.trim(), $options: "i" };
  }
  if (category !== undefined && category !== "all") {
    if (!isNonEmptyString(category, 50)) return jsonError(res, 400, "Invalid category");
    query.category = category.trim();
  }
  if (location !== undefined) {
    if (!isNonEmptyString(location, 100)) return jsonError(res, 400, "Invalid location");
    query.location = { $regex: location.trim(), $options: "i" };
  }

  let sortOption = { createdAt: -1 };
  if (sort !== undefined) {
    if (!["asc", "desc", "newest"].includes(String(sort))) return jsonError(res, 400, "Invalid sort");
    if (sort === "asc") sortOption = { price: 1, createdAt: -1 };
    if (sort === "desc") sortOption = { price: -1, createdAt: -1 };
  }

  const services = await collections.services.find(query).sort(sortOption).toArray();
  return res.json(services.map(sanitizeService));
}));

app.get("/services/vendor", verifyToken, verifyRole(["vendor"]), asyncHandler(async (req, res) => {
  const services = await collections.services
    .find({ vendorId: asIdString(req.user._id) })
    .sort({ createdAt: -1 })
    .toArray();
  return res.json(services);
}));

app.get("/services/:id", asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return jsonError(res, 400, "Invalid service id");
  const service = await collections.services.findOne({ _id: toObjectId(id) });
  if (!service) return jsonError(res, 404, "Service not found");
  if (service.status !== "approved" || service.isActive !== true) {
    return jsonError(res, 404, "Service not found");
  }
  return res.json(service);
}));

app.post("/services", verifyToken, verifyRole(["vendor"]), asyncHandler(async (req, res) => {
  const { serviceName, category, description, price, location, images } = req.body || {};
  if (!isNonEmptyString(serviceName, 120)) return jsonError(res, 400, "serviceName is required");
  if (!isNonEmptyString(category, 60)) return jsonError(res, 400, "category is required");
  if (!isNonEmptyString(description, 5000)) return jsonError(res, 400, "description is required");
  if (!isNonEmptyString(location, 200)) return jsonError(res, 400, "location is required");
  const priceNum = parsePositiveNumber(price);
  if (priceNum === null) return jsonError(res, 400, "price must be a non-negative number");
  if (images !== undefined && !Array.isArray(images)) return jsonError(res, 400, "images must be an array");
  const safeImages = Array.isArray(images)
    ? images.filter((i) => typeof i === "string" && i.trim()).slice(0, 10)
    : [];

  const premium = isPremiumActive(req.user);
  if (!premium) {
    const activeCount = await collections.services.countDocuments({
      vendorId: asIdString(req.user._id),
      isActive: true,
      status: { $in: ["pending", "approved"] },
    });
    if (activeCount >= 3) return jsonError(res, 403, "Free plan limit reached (max 3 active services)");
  }

  const newService = {
    vendorId: asIdString(req.user._id),
    serviceName: serviceName.trim(),
    category: category.trim(),
    description: description.trim(),
    price: priceNum,
    location: location.trim(),
    images: safeImages,
    status: "pending",
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const result = await collections.services.insertOne(newService);
  return res.status(201).json({ ...newService, _id: result.insertedId });
}));

app.patch("/services/:id", verifyToken, verifyRole(["vendor"]), asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return jsonError(res, 400, "Invalid service id");

  const service = await collections.services.findOne({ _id: toObjectId(id) });
  if (!service) return jsonError(res, 404, "Service not found");
  if (!sameId(service.vendorId, req.user._id)) return jsonError(res, 403, "Forbidden: not service owner");

  const body = req.body || {};
  const update = {};

  if (body.serviceName !== undefined) {
    if (!isNonEmptyString(body.serviceName, 120)) return jsonError(res, 400, "Invalid serviceName");
    update.serviceName = body.serviceName.trim();
  }
  if (body.category !== undefined) {
    if (!isNonEmptyString(body.category, 60)) return jsonError(res, 400, "Invalid category");
    update.category = body.category.trim();
  }
  if (body.description !== undefined) {
    if (!isNonEmptyString(body.description, 5000)) return jsonError(res, 400, "Invalid description");
    update.description = body.description.trim();
  }
  if (body.location !== undefined) {
    if (!isNonEmptyString(body.location, 200)) return jsonError(res, 400, "Invalid location");
    update.location = body.location.trim();
  }
  if (body.price !== undefined) {
    const priceNum = parsePositiveNumber(body.price);
    if (priceNum === null) return jsonError(res, 400, "Invalid price");
    update.price = priceNum;
  }
  if (body.images !== undefined) {
    if (!Array.isArray(body.images)) return jsonError(res, 400, "images must be an array");
    update.images = body.images.filter((i) => typeof i === "string" && i.trim()).slice(0, 10);
  }
  if (body.isActive !== undefined) {
    if (typeof body.isActive !== "boolean") return jsonError(res, 400, "isActive must be boolean");
    update.isActive = body.isActive;
  }

  if (Object.keys(update).length === 0) return jsonError(res, 400, "No valid fields to update");

  const willBeActive = update.isActive === undefined ? service.isActive : update.isActive;
  const premium = isPremiumActive(req.user);
  if (!premium) {
    const isCurrentlyActiveCounted = service.isActive && ["pending", "approved"].includes(service.status);
    const willBeActiveCounted = willBeActive && ["pending", "approved"].includes(service.status);
    if (!isCurrentlyActiveCounted && willBeActiveCounted) {
      const activeCount = await collections.services.countDocuments({
        vendorId: asIdString(req.user._id),
        isActive: true,
        status: { $in: ["pending", "approved"] },
        _id: { $ne: service._id },
      });
      if (activeCount >= 3) return jsonError(res, 403, "Free plan limit reached (max 3 active services)");
    }
  }

  update.updatedAt = new Date();
  await collections.services.updateOne({ _id: service._id }, { $set: update });
  const updated = await collections.services.findOne({ _id: service._id });
  return res.json(updated);
}));

app.delete("/services/:id", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return jsonError(res, 400, "Invalid service id");
  const service = await collections.services.findOne({ _id: toObjectId(id) });
  if (!service) return jsonError(res, 404, "Service not found");
  const result = await collections.services.deleteOne({ _id: service._id });
  return res.json({ deleted: result.deletedCount === 1, serviceId: id });
}));

app.patch("/services/:id/status", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  if (!isValidObjectId(id)) return jsonError(res, 400, "Invalid service id");
  if (!["approved", "rejected"].includes(status)) return jsonError(res, 400, "status must be approved or rejected");

  const service = await collections.services.findOne({ _id: toObjectId(id) });
  if (!service) return jsonError(res, 404, "Service not found");

  await collections.services.updateOne({ _id: service._id }, { $set: { status, updatedAt: new Date() } });
  const updated = await collections.services.findOne({ _id: service._id });
  return res.json(updated);
}));
// BOOKINGS
app.post("/bookings", verifyToken, verifyRole(["customer"]), asyncHandler(async (req, res) => {
  const { serviceId, eventDate, eventLocation, message } = req.body || {};
  if (!isValidObjectId(serviceId)) return jsonError(res, 400, "Invalid serviceId");
  if (!isValidDateString(eventDate)) return jsonError(res, 400, "Invalid eventDate");
  if (!isNonEmptyString(eventLocation, 200)) return jsonError(res, 400, "eventLocation is required");
  if (message !== undefined && !isNonEmptyString(message, 2000)) return jsonError(res, 400, "Invalid message");

  const service = await collections.services.findOne({ _id: toObjectId(serviceId) });
  if (!service || service.status !== "approved" || service.isActive !== true) {
    return jsonError(res, 404, "Service not available");
  }
  if (sameId(service.vendorId, req.user._id)) {
    return jsonError(res, 403, "Customers cannot book their own services");
  }

  const duplicate = await collections.bookings.findOne({
    serviceId: asIdString(service._id),
    eventDate: String(eventDate),
    status: { $in: ["pending", "accepted"] },
  });
  if (duplicate) {
    return jsonError(res, 409, "An active booking already exists for this service/date");
  }

  const booking = {
    serviceId: asIdString(service._id),
    vendorId: asIdString(service.vendorId),
    customerId: asIdString(req.user._id),
    eventDate: String(eventDate),
    eventLocation: eventLocation.trim(),
    message: typeof message === "string" ? message.trim() : "",
    status: "pending",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const result = await collections.bookings.insertOne(booking);
  return res.status(201).json({ ...booking, _id: result.insertedId });
}));

app.get("/bookings/customer", verifyToken, verifyRole(["customer"]), asyncHandler(async (req, res) => {
  const bookings = await collections.bookings
    .find({ customerId: asIdString(req.user._id) })
    .sort({ createdAt: -1 })
    .toArray();
  return res.json(bookings);
}));

app.get("/bookings/vendor", verifyToken, verifyRole(["vendor"]), asyncHandler(async (req, res) => {
  const bookings = await collections.bookings
    .find({ vendorId: asIdString(req.user._id) })
    .sort({ createdAt: -1 })
    .toArray();
  return res.json(bookings);
}));

app.patch("/bookings/:id/status", verifyToken, verifyRole(["vendor"]), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  if (!isValidObjectId(id)) return jsonError(res, 400, "Invalid booking id");
  if (!["accepted", "rejected"].includes(status)) return jsonError(res, 400, "status must be accepted or rejected");

  const booking = await collections.bookings.findOne({ _id: toObjectId(id) });
  if (!booking) return jsonError(res, 404, "Booking not found");
  if (!sameId(booking.vendorId, req.user._id)) return jsonError(res, 403, "Forbidden: not booking owner");
  if (booking.status !== "pending") return jsonError(res, 400, "Only pending bookings can be processed");

  await collections.bookings.updateOne(
    { _id: booking._id },
    { $set: { status, updatedAt: new Date() } }
  );
  const updated = await collections.bookings.findOne({ _id: booking._id });
  return res.json(updated);
}));

app.patch("/bookings/:id/cancel", verifyToken, verifyRole(["customer"]), asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return jsonError(res, 400, "Invalid booking id");

  const booking = await collections.bookings.findOne({ _id: toObjectId(id) });
  if (!booking) return jsonError(res, 404, "Booking not found");
  if (!sameId(booking.customerId, req.user._id)) return jsonError(res, 403, "Forbidden: not booking owner");
  if (booking.status !== "pending") return jsonError(res, 400, "Only pending bookings can be cancelled");

  await collections.bookings.updateOne(
    { _id: booking._id },
    { $set: { status: "cancelled", updatedAt: new Date() } }
  );
  const updated = await collections.bookings.findOne({ _id: booking._id });
  return res.json(updated);
}));
// ADMIN
app.get("/admin/stats", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const [totalUsers, totalVendors, totalCustomers, totalServices, pendingServices, approvedServices, rejectedServices, totalBookings, totalTransactions, revenueAgg] = await Promise.all([
    collections.users.countDocuments(),
    collections.users.countDocuments({ role: "vendor" }),
    collections.users.countDocuments({ role: "customer" }),
    collections.services.countDocuments(),
    collections.services.countDocuments({ status: "pending" }),
    collections.services.countDocuments({ status: "approved" }),
    collections.services.countDocuments({ status: "rejected" }),
    collections.bookings.countDocuments(),
    collections.transactions.countDocuments({ status: "success" }),
    collections.transactions.aggregate([
      { $match: { status: "success" } },
      { $group: { _id: null, total: { $sum: "$amount" } } },
    ]).toArray(),
  ]);

  return res.json({
    totalUsers,
    totalVendors,
    totalCustomers,
    totalServices,
    pendingServices,
    approvedServices,
    rejectedServices,
    totalBookings,
    totalTransactions,
    totalRevenue: revenueAgg[0]?.total || 0,
  });
}));

app.get("/admin/users", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const { search, role } = req.query;
  const query = {};
  if (search !== undefined) {
    if (!isNonEmptyString(search, 100)) return jsonError(res, 400, "Invalid search");
    const s = search.trim();
    query.$or = [
      { name: { $regex: s, $options: "i" } },
      { email: { $regex: s, $options: "i" } },
    ];
  }
  if (role !== undefined && role !== "all") {
    if (!VALID_ROLES.includes(String(role))) return jsonError(res, 400, "Invalid role filter");
    query.role = String(role);
  }
  const users = await collections.users.find(query).sort({ createdAt: -1 }).toArray();
  return res.json(users.map(sanitizeUser));
}));

app.patch("/admin/users/:id/block", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id) && typeof id !== "string") return jsonError(res, 400, "Invalid user id");
  const user = await findUserById(id);
  if (!user) return jsonError(res, 404, "User not found");
  if (sameId(user._id, req.user._id)) return jsonError(res, 400, "Admin cannot block self");

  const nextBlocked = !user.isBlocked;
  await collections.users.updateOne({ _id: user._id }, { $set: { isBlocked: nextBlocked, updatedAt: new Date() } });
  const updated = await collections.users.findOne({ _id: user._id });
  return res.json(sanitizeUser(updated));
}));

app.get("/admin/services", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const services = await collections.services.find().sort({ createdAt: -1 }).toArray();
  return res.json(services);
}));

app.get("/admin/transactions", verifyToken, verifyRole(["admin"]), asyncHandler(async (req, res) => {
  const transactions = await collections.transactions.find().sort({ createdAt: -1 }).toArray();
  return res.json(transactions);
}));

// PAYMENTS
app.post("/payments/create-checkout-session", verifyToken, verifyRole(["vendor"]), asyncHandler(async (req, res) => {
  if (!ensureStripe(res)) return;
  const vendorId = asIdString(req.user._id);
  if (!vendorId) return jsonError(res, 400, "Invalid vendor");

  if (isPremiumActive(req.user)) {
    return jsonError(res, 400, "Vendor already has active premium subscription");
  }

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    mode: "subscription",
    customer_email: req.user.email || undefined,
    line_items: [{
      price_data: {
        currency: "usd",
        product_data: { name: "VowVista Premium Subscription" },
        unit_amount: 500,
        recurring: { interval: "month" },
      },
      quantity: 1,
    }],
    metadata: { vendorId },
    success_url: `${process.env.CLIENT_URL.split(",")[0].trim()}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.CLIENT_URL.split(",")[0].trim()}/payment/cancel`,
  });

  return res.json({ url: session.url, sessionId: session.id });
}));

//Protect transaction immutability at API layer
app.all("/admin/transactions/:id", verifyToken, verifyRole(["admin"]), (req, res) => {
  return jsonError(res, 405, "Transactions are immutable");
});
app.all("/transactions", (req, res) => jsonError(res, 404, "Not found"));
app.all("/transactions/:id", (req, res) => jsonError(res, 404, "Not found"));

// 404 + error handler
app.use((req, res) => jsonError(res, 404, "Route not found"));

app.use((err, req, res, next) => {
  console.error("API Error:", err);
  if (res.headersSent) return next(err);
  if (err?.type === "entity.parse.failed") return jsonError(res, 400, "Invalid JSON body");
  const status = Number(err?.status) || 500;
  return jsonError(res, status, status === 500 ? "Internal server error" : err.message);
});

async function startServer() {
  await connectDB();
  app.listen(port, () => console.log(`VowVista server running on port ${port}`));
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
