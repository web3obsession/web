var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  cryptocurrencies: () => cryptocurrencies,
  cryptocurrenciesRelations: () => cryptocurrenciesRelations,
  insertCryptocurrencySchema: () => insertCryptocurrencySchema,
  insertOrderSchema: () => insertOrderSchema,
  insertSwapSessionSchema: () => insertSwapSessionSchema,
  insertTradingPairSchema: () => insertTradingPairSchema,
  insertTransactionSchema: () => insertTransactionSchema,
  insertUserSchema: () => insertUserSchema,
  insertWalletSchema: () => insertWalletSchema,
  orders: () => orders,
  ordersRelations: () => ordersRelations,
  priceHistory: () => priceHistory,
  sessions: () => sessions,
  swapSessions: () => swapSessions,
  tradingPairs: () => tradingPairs,
  tradingPairsRelations: () => tradingPairsRelations,
  transactionTypes: () => transactionTypes,
  transactions: () => transactions,
  transactionsRelations: () => transactionsRelations,
  users: () => users,
  usersRelations: () => usersRelations,
  wallets: () => wallets,
  walletsRelations: () => walletsRelations
});
import {
  pgTable,
  varchar,
  timestamp,
  jsonb,
  index,
  serial,
  decimal,
  boolean,
  integer
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { relations } from "drizzle-orm";
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var users = pgTable("users", {
  id: varchar("id").primaryKey().notNull(),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var cryptocurrencies = pgTable("cryptocurrencies", {
  id: serial("id").primaryKey(),
  symbol: varchar("symbol", { length: 10 }).notNull().unique(),
  name: varchar("name", { length: 100 }).notNull(),
  network: varchar("network", { length: 50 }).notNull(),
  decimals: integer("decimals").notNull().default(8),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow()
});
var wallets = pgTable("wallets", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull().references(() => users.id),
  cryptoId: integer("crypto_id").notNull().references(() => cryptocurrencies.id),
  address: varchar("address", { length: 255 }).notNull(),
  balance: decimal("balance", { precision: 20, scale: 8 }).notNull().default("0"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var transactionTypes = pgTable("transaction_types", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 50 }).notNull().unique()
  // deposit, withdraw, trade, swap
});
var transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").references(() => users.id),
  typeId: integer("type_id").notNull().references(() => transactionTypes.id),
  cryptoId: integer("crypto_id").notNull().references(() => cryptocurrencies.id),
  amount: decimal("amount", { precision: 20, scale: 8 }).notNull(),
  fee: decimal("fee", { precision: 20, scale: 8 }).notNull().default("0"),
  status: varchar("status", { length: 20 }).notNull().default("pending"),
  // pending, completed, failed, cancelled
  externalTxId: varchar("external_tx_id", { length: 255 }),
  fromAddress: varchar("from_address", { length: 255 }),
  toAddress: varchar("to_address", { length: 255 }),
  metadata: jsonb("metadata"),
  // Additional data like swap details
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var tradingPairs = pgTable("trading_pairs", {
  id: serial("id").primaryKey(),
  baseCryptoId: integer("base_crypto_id").notNull().references(() => cryptocurrencies.id),
  quoteCryptoId: integer("quote_crypto_id").notNull().references(() => cryptocurrencies.id),
  symbol: varchar("symbol", { length: 20 }).notNull().unique(),
  // BTC/USDT
  isActive: boolean("is_active").notNull().default(true),
  minOrderSize: decimal("min_order_size", { precision: 20, scale: 8 }).notNull(),
  maxOrderSize: decimal("max_order_size", { precision: 20, scale: 8 }),
  priceDecimals: integer("price_decimals").notNull().default(2),
  amountDecimals: integer("amount_decimals").notNull().default(8),
  createdAt: timestamp("created_at").defaultNow()
});
var orders = pgTable("orders", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").references(() => users.id),
  pairId: integer("pair_id").notNull().references(() => tradingPairs.id),
  type: varchar("type", { length: 10 }).notNull(),
  // buy, sell
  orderType: varchar("order_type", { length: 10 }).notNull(),
  // market, limit
  amount: decimal("amount", { precision: 20, scale: 8 }).notNull(),
  price: decimal("price", { precision: 20, scale: 8 }),
  filled: decimal("filled", { precision: 20, scale: 8 }).notNull().default("0"),
  status: varchar("status", { length: 20 }).notNull().default("active"),
  // active, filled, cancelled, partial
  isLiquidityOrder: boolean("is_liquidity_order").notNull().default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var priceHistory = pgTable("price_history", {
  id: serial("id").primaryKey(),
  pairId: integer("pair_id").notNull().references(() => tradingPairs.id),
  price: decimal("price", { precision: 20, scale: 8 }).notNull(),
  volume: decimal("volume", { precision: 20, scale: 8 }).notNull().default("0"),
  timestamp: timestamp("timestamp").notNull().defaultNow()
});
var swapSessions = pgTable("swap_sessions", {
  id: serial("id").primaryKey(),
  sessionId: varchar("session_id", { length: 255 }).notNull().unique(),
  fromCryptoId: integer("from_crypto_id").notNull().references(() => cryptocurrencies.id),
  toCryptoId: integer("to_crypto_id").notNull().references(() => cryptocurrencies.id),
  fromAmount: decimal("from_amount", { precision: 20, scale: 8 }).notNull(),
  toAmount: decimal("to_amount", { precision: 20, scale: 8 }).notNull(),
  exchangeRate: decimal("exchange_rate", { precision: 20, scale: 8 }).notNull(),
  fee: decimal("fee", { precision: 20, scale: 8 }).notNull(),
  depositAddress: varchar("deposit_address", { length: 255 }).notNull(),
  withdrawalAddress: varchar("withdrawal_address", { length: 255 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("pending"),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var usersRelations = relations(users, ({ many }) => ({
  wallets: many(wallets),
  transactions: many(transactions),
  orders: many(orders)
}));
var cryptocurrenciesRelations = relations(cryptocurrencies, ({ many }) => ({
  wallets: many(wallets),
  transactions: many(transactions),
  basePairs: many(tradingPairs, { relationName: "baseCrypto" }),
  quotePairs: many(tradingPairs, { relationName: "quoteCrypto" })
}));
var walletsRelations = relations(wallets, ({ one }) => ({
  user: one(users, {
    fields: [wallets.userId],
    references: [users.id]
  }),
  cryptocurrency: one(cryptocurrencies, {
    fields: [wallets.cryptoId],
    references: [cryptocurrencies.id]
  })
}));
var tradingPairsRelations = relations(tradingPairs, ({ one, many }) => ({
  baseCrypto: one(cryptocurrencies, {
    fields: [tradingPairs.baseCryptoId],
    references: [cryptocurrencies.id],
    relationName: "baseCrypto"
  }),
  quoteCrypto: one(cryptocurrencies, {
    fields: [tradingPairs.quoteCryptoId],
    references: [cryptocurrencies.id],
    relationName: "quoteCrypto"
  }),
  orders: many(orders),
  priceHistory: many(priceHistory)
}));
var ordersRelations = relations(orders, ({ one }) => ({
  user: one(users, {
    fields: [orders.userId],
    references: [users.id]
  }),
  pair: one(tradingPairs, {
    fields: [orders.pairId],
    references: [tradingPairs.id]
  })
}));
var transactionsRelations = relations(transactions, ({ one }) => ({
  user: one(users, {
    fields: [transactions.userId],
    references: [users.id]
  }),
  cryptocurrency: one(cryptocurrencies, {
    fields: [transactions.cryptoId],
    references: [cryptocurrencies.id]
  }),
  type: one(transactionTypes, {
    fields: [transactions.typeId],
    references: [transactionTypes.id]
  })
}));
var insertUserSchema = createInsertSchema(users);
var insertCryptocurrencySchema = createInsertSchema(cryptocurrencies).omit({ id: true, createdAt: true });
var insertWalletSchema = createInsertSchema(wallets).omit({ id: true, createdAt: true, updatedAt: true });
var insertTransactionSchema = createInsertSchema(transactions).omit({ id: true, createdAt: true, updatedAt: true });
var insertOrderSchema = createInsertSchema(orders).omit({ id: true, createdAt: true, updatedAt: true });
var insertTradingPairSchema = createInsertSchema(tradingPairs).omit({ id: true, createdAt: true });
var insertSwapSessionSchema = createInsertSchema(swapSessions).omit({ id: true, createdAt: true, updatedAt: true });

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq, desc, and, gte } from "drizzle-orm";
var DatabaseStorage = class {
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async upsertUser(userData) {
    const [user] = await db.insert(users).values(userData).onConflictDoUpdate({
      target: users.id,
      set: {
        ...userData,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    return user;
  }
  async getCryptocurrencies() {
    return await db.select().from(cryptocurrencies).where(eq(cryptocurrencies.isActive, true));
  }
  async getCryptocurrencyBySymbol(symbol) {
    const [crypto] = await db.select().from(cryptocurrencies).where(eq(cryptocurrencies.symbol, symbol));
    return crypto;
  }
  async getUserWallets(userId) {
    return await db.query.wallets.findMany({
      where: eq(wallets.userId, userId),
      with: {
        cryptocurrency: true
      }
    });
  }
  async getWallet(userId, cryptoId) {
    const [wallet] = await db.select().from(wallets).where(and(eq(wallets.userId, userId), eq(wallets.cryptoId, cryptoId)));
    return wallet;
  }
  async createWallet(walletData) {
    const [wallet] = await db.insert(wallets).values(walletData).returning();
    return wallet;
  }
  async updateWalletBalance(walletId, balance) {
    await db.update(wallets).set({ balance, updatedAt: /* @__PURE__ */ new Date() }).where(eq(wallets.id, walletId));
  }
  async createTransaction(transactionData) {
    const [transaction] = await db.insert(transactions).values(transactionData).returning();
    return transaction;
  }
  async getUserTransactions(userId, limit = 50) {
    return await db.query.transactions.findMany({
      where: eq(transactions.userId, userId),
      with: {
        cryptocurrency: true
      },
      orderBy: [desc(transactions.createdAt)],
      limit
    });
  }
  async updateTransactionStatus(transactionId, status) {
    await db.update(transactions).set({ status, updatedAt: /* @__PURE__ */ new Date() }).where(eq(transactions.id, transactionId));
  }
  async getTradingPairs() {
    return await db.query.tradingPairs.findMany({
      where: eq(tradingPairs.isActive, true),
      with: {
        baseCrypto: true,
        quoteCrypto: true
      }
    });
  }
  async getTradingPair(id) {
    return await db.query.tradingPairs.findFirst({
      where: eq(tradingPairs.id, id),
      with: {
        baseCrypto: true,
        quoteCrypto: true
      }
    });
  }
  async getTradingPairBySymbol(symbol) {
    return await db.query.tradingPairs.findFirst({
      where: eq(tradingPairs.symbol, symbol),
      with: {
        baseCrypto: true,
        quoteCrypto: true
      }
    });
  }
  async createOrder(orderData) {
    const [order] = await db.insert(orders).values(orderData).returning();
    return order;
  }
  async getUserOrders(userId) {
    return await db.query.orders.findMany({
      where: eq(orders.userId, userId),
      with: {
        pair: true
      },
      orderBy: [desc(orders.createdAt)]
    });
  }
  async getOrderBook(pairId) {
    const allOrders = await db.select().from(orders).where(and(eq(orders.pairId, pairId), eq(orders.status, "active"))).orderBy(orders.price);
    const bids = allOrders.filter((order) => order.type === "buy").reverse();
    const asks = allOrders.filter((order) => order.type === "sell");
    return { bids, asks };
  }
  async updateOrderStatus(orderId, status, filled) {
    const updateData = { status, updatedAt: /* @__PURE__ */ new Date() };
    if (filled !== void 0) {
      updateData.filled = filled;
    }
    await db.update(orders).set(updateData).where(eq(orders.id, orderId));
  }
  async cancelOrder(orderId, userId) {
    const result = await db.update(orders).set({ status: "cancelled", updatedAt: /* @__PURE__ */ new Date() }).where(and(eq(orders.id, orderId), eq(orders.userId, userId), eq(orders.status, "active")));
    return (result.rowCount ?? 0) > 0;
  }
  async getLiquidityOrders(pairId) {
    return await db.select().from(orders).where(and(eq(orders.pairId, pairId), eq(orders.isLiquidityOrder, true), eq(orders.status, "active")));
  }
  async deleteLiquidityOrders(pairId) {
    await db.delete(orders).where(and(eq(orders.pairId, pairId), eq(orders.isLiquidityOrder, true)));
  }
  async getCurrentPrice(pairId) {
    const [result] = await db.select({ price: priceHistory.price }).from(priceHistory).where(eq(priceHistory.pairId, pairId)).orderBy(desc(priceHistory.timestamp)).limit(1);
    return result?.price;
  }
  async addPriceHistory(pairId, price, volume) {
    await db.insert(priceHistory).values({
      pairId,
      price,
      volume,
      timestamp: /* @__PURE__ */ new Date()
    });
  }
  async getPriceHistory(pairId, hours) {
    const since = new Date(Date.now() - hours * 60 * 60 * 1e3);
    return await db.select().from(priceHistory).where(and(eq(priceHistory.pairId, pairId), gte(priceHistory.timestamp, since))).orderBy(priceHistory.timestamp);
  }
  async createSwapSession(sessionData) {
    const [session2] = await db.insert(swapSessions).values(sessionData).returning();
    return session2;
  }
  async getSwapSession(sessionId) {
    const [session2] = await db.select().from(swapSessions).where(eq(swapSessions.sessionId, sessionId));
    return session2;
  }
  async updateSwapSession(sessionId, data) {
    await db.update(swapSessions).set({ ...data, updatedAt: /* @__PURE__ */ new Date() }).where(eq(swapSessions.sessionId, sessionId));
  }
  async initializeDefaultData() {
    const txTypes = [
      { name: "deposit" },
      { name: "withdraw" },
      { name: "trade" },
      { name: "swap" }
    ];
    for (const type of txTypes) {
      await db.insert(transactionTypes).values(type).onConflictDoNothing();
    }
    const cryptos = [
      { symbol: "BTC", name: "Bitcoin", network: "Bitcoin", decimals: 8 },
      { symbol: "ETH", name: "Ethereum", network: "Ethereum", decimals: 18 },
      { symbol: "BASE", name: "Base", network: "Base", decimals: 18 },
      { symbol: "USDT", name: "Tether USD", network: "Ethereum", decimals: 6 }
    ];
    for (const crypto of cryptos) {
      await db.insert(cryptocurrencies).values(crypto).onConflictDoNothing();
    }
    const btc = await this.getCryptocurrencyBySymbol("BTC");
    const eth = await this.getCryptocurrencyBySymbol("ETH");
    const base = await this.getCryptocurrencyBySymbol("BASE");
    const usdt = await this.getCryptocurrencyBySymbol("USDT");
    if (btc && eth && base && usdt) {
      const pairs = [
        {
          baseCryptoId: btc.id,
          quoteCryptoId: usdt.id,
          symbol: "BTC/USDT",
          minOrderSize: "0.0001",
          maxOrderSize: "1000",
          priceDecimals: 2,
          amountDecimals: 8
        },
        {
          baseCryptoId: eth.id,
          quoteCryptoId: usdt.id,
          symbol: "ETH/USDT",
          minOrderSize: "0.001",
          maxOrderSize: "10000",
          priceDecimals: 2,
          amountDecimals: 8
        },
        {
          baseCryptoId: base.id,
          quoteCryptoId: usdt.id,
          symbol: "BASE/USDT",
          minOrderSize: "1",
          maxOrderSize: "1000000",
          priceDecimals: 4,
          amountDecimals: 2
        }
      ];
      for (const pair of pairs) {
        await db.insert(tradingPairs).values(pair).onConflictDoNothing();
      }
      const now = /* @__PURE__ */ new Date();
      const btcPair = await this.getTradingPairBySymbol("BTC/USDT");
      const ethPair = await this.getTradingPairBySymbol("ETH/USDT");
      const basePair = await this.getTradingPairBySymbol("BASE/USDT");
      if (btcPair) {
        await db.insert(priceHistory).values({
          pairId: btcPair.id,
          price: "43122.45",
          volume: "1500.5",
          timestamp: now
        }).onConflictDoNothing();
      }
      if (ethPair) {
        await db.insert(priceHistory).values({
          pairId: ethPair.id,
          price: "1905.67",
          volume: "2300.2",
          timestamp: now
        }).onConflictDoNothing();
      }
      if (basePair) {
        await db.insert(priceHistory).values({
          pairId: basePair.id,
          price: "17.2548",
          volume: "45000.8",
          timestamp: now
        }).onConflictDoNothing();
      }
    }
  }
};
var storage = new DatabaseStorage();

// server/replitAuth.ts
import * as client from "openid-client";
import { Strategy } from "openid-client/passport";
import passport from "passport";
import session from "express-session";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
if (!process.env.REPLIT_DOMAINS) {
  throw new Error("Environment variable REPLIT_DOMAINS not provided");
}
var getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID
    );
  },
  { maxAge: 3600 * 1e3 }
);
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      maxAge: sessionTtl
    }
  });
}
function updateUserSession(user, tokens) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}
async function upsertUser(claims) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"]
  });
}
async function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.use(passport.initialize());
  app2.use(passport.session());
  const config = await getOidcConfig();
  const verify = async (tokens, verified) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };
  for (const domain of process.env.REPLIT_DOMAINS.split(",")) {
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`
      },
      verify
    );
    passport.use(strategy);
  }
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));
  app2.get("/api/login", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"]
    })(req, res, next);
  });
  app2.get("/api/callback", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login"
    })(req, res, next);
  });
  app2.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`
        }).href
      );
    });
  });
}
var isAuthenticated = async (req, res, next) => {
  const user = req.user;
  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const now = Math.floor(Date.now() / 1e3);
  if (now <= user.expires_at) {
    return next();
  }
  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};

// server/services/liquidityService.ts
var LiquidityService = class {
  isRunning = false;
  config = {
    maxSpreadPercent: 8,
    maxVolumePercent: 50,
    updateInterval: 5 * 60 * 1e3
    // 5 minutes
  };
  async start(storage2, broadcastUpdate) {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log("Liquidity service started");
    await this.manageLiquidity(storage2, broadcastUpdate);
    setInterval(async () => {
      if (this.isRunning) {
        await this.manageLiquidity(storage2, broadcastUpdate);
      }
    }, this.config.updateInterval);
  }
  stop() {
    this.isRunning = false;
    console.log("Liquidity service stopped");
  }
  async manageLiquidity(storage2, broadcastUpdate) {
    try {
      const pairs = await storage2.getTradingPairs();
      for (const pair of pairs) {
        await this.managePairLiquidity(storage2, pair.id, broadcastUpdate);
      }
    } catch (error) {
      console.error("Error managing liquidity:", error);
    }
  }
  async managePairLiquidity(storage2, pairId, broadcastUpdate) {
    try {
      const orderBook = await storage2.getOrderBook(pairId);
      const currentPrice = await storage2.getCurrentPrice(pairId);
      if (!currentPrice) return;
      const price = parseFloat(currentPrice);
      const spread = this.calculateSpread(orderBook.bids, orderBook.asks, price);
      if (spread > this.config.maxSpreadPercent) {
        await storage2.deleteLiquidityOrders(pairId);
        const liquidityOrders = this.calculateLiquidityOrders(
          price,
          orderBook.bids,
          orderBook.asks
        );
        for (const order of liquidityOrders) {
          await storage2.createOrder({
            userId: null,
            // System orders
            pairId,
            type: order.type,
            orderType: "limit",
            amount: order.amount,
            price: order.price,
            isLiquidityOrder: true
          });
        }
        const updatedOrderBook = await storage2.getOrderBook(pairId);
        broadcastUpdate({
          type: "orderbook",
          pairId,
          data: updatedOrderBook
        });
        console.log(`Added liquidity for pair ${pairId}, spread was ${spread.toFixed(2)}%`);
      }
    } catch (error) {
      console.error(`Error managing liquidity for pair ${pairId}:`, error);
    }
  }
  calculateSpread(bids, asks, currentPrice) {
    if (bids.length === 0 || asks.length === 0) return 100;
    const bestBid = Math.max(...bids.map((b) => parseFloat(b.price)));
    const bestAsk = Math.min(...asks.map((a) => parseFloat(a.price)));
    return (bestAsk - bestBid) / currentPrice * 100;
  }
  calculateLiquidityOrders(currentPrice, existingBids, existingAsks) {
    const orders2 = [];
    const levels = [0.5, 1, 1.5, 2];
    for (const level of levels) {
      const bidPrice = currentPrice * (1 - level / 100);
      const askPrice = currentPrice * (1 + level / 100);
      const bidAmount = this.calculateOrderAmount(existingBids, bidPrice);
      const askAmount = this.calculateOrderAmount(existingAsks, askPrice);
      if (bidAmount > 0) {
        orders2.push({
          type: "buy",
          price: bidPrice.toFixed(2),
          amount: bidAmount.toFixed(8)
        });
      }
      if (askAmount > 0) {
        orders2.push({
          type: "sell",
          price: askPrice.toFixed(2),
          amount: askAmount.toFixed(8)
        });
      }
    }
    return orders2;
  }
  calculateOrderAmount(existingOrders, targetPrice) {
    const adjacentOrders = existingOrders.filter((order) => {
      const orderPrice = parseFloat(order.price);
      return Math.abs(orderPrice - targetPrice) < targetPrice * 0.02;
    });
    if (adjacentOrders.length === 0) {
      return 0.1;
    }
    const avgVolume = adjacentOrders.reduce((sum, order) => sum + parseFloat(order.amount), 0) / adjacentOrders.length;
    return Math.min(avgVolume * this.config.maxVolumePercent / 100, 1);
  }
};
var liquidityService = new LiquidityService();

// server/services/priceService.ts
var PriceService = class {
  isRunning = false;
  prices = {
    "BTC": 43122.45,
    "ETH": 1905.67,
    "BASE": 17.2548,
    "USDT": 1
  };
  updateInterval = 1e4;
  // 10 seconds
  async start(storage2, broadcastUpdate) {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log("Price service started");
    setInterval(async () => {
      if (this.isRunning) {
        await this.updatePrices(storage2, broadcastUpdate);
      }
    }, this.updateInterval);
  }
  stop() {
    this.isRunning = false;
    console.log("Price service stopped");
  }
  getExchangeRate(fromSymbol, toSymbol) {
    if (fromSymbol === toSymbol) return 1;
    const fromPrice = this.prices[fromSymbol] || 1;
    const toPrice = this.prices[toSymbol] || 1;
    return fromPrice / toPrice;
  }
  getCurrentPrice(symbol) {
    return this.prices[symbol] || 0;
  }
  async updatePrices(storage2, broadcastUpdate) {
    try {
      for (const symbol of Object.keys(this.prices)) {
        const currentPrice = this.prices[symbol];
        const change = (Math.random() - 0.5) * 0.02;
        const newPrice = currentPrice * (1 + change);
        this.prices[symbol] = Math.max(newPrice, 0.01);
      }
      const pairs = await storage2.getTradingPairs();
      for (const pair of pairs) {
        const basePrice = this.prices[pair.baseCrypto.symbol];
        const quotePrice = this.prices[pair.quoteCrypto.symbol];
        if (basePrice && quotePrice) {
          const pairPrice = basePrice / quotePrice;
          const volume = Math.random() * 100;
          await storage2.addPriceHistory(pair.id, pairPrice.toFixed(2), volume.toFixed(2));
        }
      }
      broadcastUpdate({
        type: "price_update",
        data: this.prices
      });
    } catch (error) {
      console.error("Error updating prices:", error);
    }
  }
};
var priceService = new PriceService();

// server/routes.ts
import { nanoid } from "nanoid";
async function registerRoutes(app2) {
  await storage.initializeDefaultData();
  await setupAuth(app2);
  const httpServer = createServer(app2);
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });
  const broadcastPriceUpdate = (data) => {
    wss.clients.forEach((client2) => {
      if (client2.readyState === WebSocket.OPEN) {
        client2.send(JSON.stringify(data));
      }
    });
  };
  wss.on("connection", (ws2) => {
    console.log("Client connected to WebSocket");
    ws2.on("close", () => {
      console.log("Client disconnected from WebSocket");
    });
  });
  liquidityService.start(storage, broadcastPriceUpdate);
  priceService.start(storage, broadcastPriceUpdate);
  app2.get("/api/auth/user", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
  app2.get("/api/cryptocurrencies", async (req, res) => {
    try {
      const cryptos = await storage.getCryptocurrencies();
      res.json(cryptos);
    } catch (error) {
      console.error("Error fetching cryptocurrencies:", error);
      res.status(500).json({ message: "Failed to fetch cryptocurrencies" });
    }
  });
  app2.get("/api/trading-pairs", async (req, res) => {
    try {
      const pairs = await storage.getTradingPairs();
      res.json(pairs);
    } catch (error) {
      console.error("Error fetching trading pairs:", error);
      res.status(500).json({ message: "Failed to fetch trading pairs" });
    }
  });
  app2.get("/api/order-book/:pairId", async (req, res) => {
    try {
      const pairId = parseInt(req.params.pairId);
      const orderBook = await storage.getOrderBook(pairId);
      res.json(orderBook);
    } catch (error) {
      console.error("Error fetching order book:", error);
      res.status(500).json({ message: "Failed to fetch order book" });
    }
  });
  app2.get("/api/price-history/:pairId", async (req, res) => {
    try {
      const pairId = parseInt(req.params.pairId);
      const hours = parseInt(req.query.hours) || 24;
      const history = await storage.getPriceHistory(pairId, hours);
      res.json(history);
    } catch (error) {
      console.error("Error fetching price history:", error);
      res.status(500).json({ message: "Failed to fetch price history" });
    }
  });
  app2.post("/api/swap/calculate", async (req, res) => {
    try {
      const { fromSymbol, toSymbol, amount } = req.body;
      const fromCrypto = await storage.getCryptocurrencyBySymbol(fromSymbol);
      const toCrypto = await storage.getCryptocurrencyBySymbol(toSymbol);
      if (!fromCrypto || !toCrypto) {
        return res.status(400).json({ message: "Invalid cryptocurrency symbols" });
      }
      const exchangeRate = priceService.getExchangeRate(fromSymbol, toSymbol);
      const fee = parseFloat(amount) * 25e-4;
      const toAmount = parseFloat(amount) * exchangeRate - fee;
      res.json({
        fromAmount: amount,
        toAmount: toAmount.toFixed(8),
        exchangeRate: exchangeRate.toFixed(8),
        fee: fee.toFixed(8),
        feePercentage: "0.25"
      });
    } catch (error) {
      console.error("Error calculating swap:", error);
      res.status(500).json({ message: "Failed to calculate swap" });
    }
  });
  app2.post("/api/swap/create", async (req, res) => {
    try {
      const validation = insertSwapSessionSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid swap data", errors: validation.error.errors });
      }
      const sessionId = nanoid();
      const depositAddress = generateMockAddress(validation.data.fromCryptoId);
      const expiresAt = new Date(Date.now() + 30 * 60 * 1e3);
      const session2 = await storage.createSwapSession({
        ...validation.data,
        sessionId,
        depositAddress,
        expiresAt
      });
      res.json({
        sessionId: session2.sessionId,
        depositAddress: session2.depositAddress,
        expiresAt: session2.expiresAt,
        fromAmount: session2.fromAmount,
        toAmount: session2.toAmount,
        withdrawalAddress: session2.withdrawalAddress
      });
    } catch (error) {
      console.error("Error creating swap session:", error);
      res.status(500).json({ message: "Failed to create swap session" });
    }
  });
  app2.get("/api/swap/:sessionId", async (req, res) => {
    try {
      const session2 = await storage.getSwapSession(req.params.sessionId);
      if (!session2) {
        return res.status(404).json({ message: "Swap session not found" });
      }
      res.json(session2);
    } catch (error) {
      console.error("Error fetching swap session:", error);
      res.status(500).json({ message: "Failed to fetch swap session" });
    }
  });
  app2.get("/api/wallets", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const wallets2 = await storage.getUserWallets(userId);
      res.json(wallets2);
    } catch (error) {
      console.error("Error fetching wallets:", error);
      res.status(500).json({ message: "Failed to fetch wallets" });
    }
  });
  app2.post("/api/wallets", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { cryptoSymbol } = req.body;
      const crypto = await storage.getCryptocurrencyBySymbol(cryptoSymbol);
      if (!crypto) {
        return res.status(400).json({ message: "Invalid cryptocurrency" });
      }
      const existingWallet = await storage.getWallet(userId, crypto.id);
      if (existingWallet) {
        return res.status(400).json({ message: "Wallet already exists for this cryptocurrency" });
      }
      const address = generateMockAddress(crypto.id);
      const wallet = await storage.createWallet({
        userId,
        cryptoId: crypto.id,
        address,
        balance: "0"
      });
      res.json(wallet);
    } catch (error) {
      console.error("Error creating wallet:", error);
      res.status(500).json({ message: "Failed to create wallet" });
    }
  });
  app2.get("/api/transactions", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const limit = parseInt(req.query.limit) || 50;
      const transactions2 = await storage.getUserTransactions(userId, limit);
      res.json(transactions2);
    } catch (error) {
      console.error("Error fetching transactions:", error);
      res.status(500).json({ message: "Failed to fetch transactions" });
    }
  });
  app2.post("/api/orders", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const validation = insertOrderSchema.safeParse({
        ...req.body,
        userId
      });
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid order data", errors: validation.error.errors });
      }
      const order = await storage.createOrder(validation.data);
      const orderBook = await storage.getOrderBook(validation.data.pairId);
      broadcastPriceUpdate({
        type: "orderbook",
        pairId: validation.data.pairId,
        data: orderBook
      });
      res.json(order);
    } catch (error) {
      console.error("Error creating order:", error);
      res.status(500).json({ message: "Failed to create order" });
    }
  });
  app2.get("/api/orders", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const orders2 = await storage.getUserOrders(userId);
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });
  app2.delete("/api/orders/:orderId", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const orderId = parseInt(req.params.orderId);
      const success = await storage.cancelOrder(orderId, userId);
      if (!success) {
        return res.status(404).json({ message: "Order not found or already cancelled" });
      }
      res.json({ message: "Order cancelled successfully" });
    } catch (error) {
      console.error("Error cancelling order:", error);
      res.status(500).json({ message: "Failed to cancel order" });
    }
  });
  app2.post("/api/deposit", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { cryptoSymbol, amount } = req.body;
      const crypto = await storage.getCryptocurrencyBySymbol(cryptoSymbol);
      if (!crypto) {
        return res.status(400).json({ message: "Invalid cryptocurrency" });
      }
      const transaction = await storage.createTransaction({
        userId,
        typeId: 1,
        // deposit
        cryptoId: crypto.id,
        amount,
        fee: "0",
        status: "completed",
        externalTxId: nanoid(),
        toAddress: generateMockAddress(crypto.id)
      });
      res.json(transaction);
    } catch (error) {
      console.error("Error processing deposit:", error);
      res.status(500).json({ message: "Failed to process deposit" });
    }
  });
  app2.post("/api/withdraw", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { cryptoSymbol, amount, address } = req.body;
      const crypto = await storage.getCryptocurrencyBySymbol(cryptoSymbol);
      if (!crypto) {
        return res.status(400).json({ message: "Invalid cryptocurrency" });
      }
      const transaction = await storage.createTransaction({
        userId,
        typeId: 2,
        // withdrawal
        cryptoId: crypto.id,
        amount,
        fee: (parseFloat(amount) * 1e-3).toString(),
        // 0.1% withdrawal fee
        status: "pending",
        externalTxId: nanoid(),
        fromAddress: generateMockAddress(crypto.id),
        toAddress: address
      });
      res.json(transaction);
    } catch (error) {
      console.error("Error processing withdrawal:", error);
      res.status(500).json({ message: "Failed to process withdrawal" });
    }
  });
  function generateMockAddress(cryptoId) {
    const addresses = {
      1: `bc1${nanoid(39)}`,
      // Bitcoin
      2: `0x${nanoid(40)}`,
      // Ethereum
      3: `0x${nanoid(40)}`,
      // Base
      4: `0x${nanoid(40)}`
      // USDT
    };
    return addresses[cryptoId] || `addr_${nanoid(20)}`;
  }
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid as nanoid2 } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid2()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
