const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const PUBLIC_DIR = path.join(__dirname, "public");
const INDEX_FILE = path.join(PUBLIC_DIR, "index.html");

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanUsername(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 40);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";

  const parts = header.split(";");

  for (const part of parts) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function setSessionCookie(res, token) {
  const maxAge = 30 * 24 * 60 * 60;

  res.setHeader(
    "Set-Cookie",
    `nv_session=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "nv_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
  );
}

function ok(res, data = {}) {
  return res.json({
    success: true,
    ...data
  });
}

function fail(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

async function createSession(userId) {
  const rawToken = randomToken(32);
  const tokenHash = hashToken(rawToken);

  await pool.query(
    `
      INSERT INTO nv_sessions
      (token_hash, user_id, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '30 days')
    `,
    [tokenHash, userId]
  );

  return rawToken;
}

async function getCurrentUser(req) {
  const rawToken = getCookie(req, "nv_session");

  if (!rawToken) {
    return null;
  }

  const tokenHash = hashToken(rawToken);

  const result = await pool.query(
    `
      SELECT
        u.id,
        u.email,
        u.username,
        u.role,
        u.points,
        u.total_completed,
        u.total_checkins,
        u.streak,
        u.last_checkin,
        u.referral_code,
        u.created_at
      FROM nv_sessions s
      JOIN nv_users u ON u.id = s.user_id
      WHERE s.token_hash = $1
        AND s.expires_at > NOW()
      LIMIT 1
    `,
    [tokenHash]
  );

  return result.rows[0] || null;
}

async function auth(req, res, next) {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      return fail(res, 401, "Vui lòng đăng nhập.");
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("AUTH ERROR:", error);
    return fail(res, 500, "Lỗi xác thực.");
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return fail(res, 403, "Bạn không có quyền quản trị.");
  }

  next();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  console.log("Initializing PostgreSQL...");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      points INTEGER NOT NULL DEFAULT 0,
      total_completed INTEGER NOT NULL DEFAULT 0,
      total_checkins INTEGER NOT NULL DEFAULT 0,
      streak INTEGER NOT NULL DEFAULT 0,
      last_checkin DATE,
      referral_code TEXT UNIQUE,
      referred_by INTEGER REFERENCES nv_users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_sessions (
      id SERIAL PRIMARY KEY,
      token_hash TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL REFERENCES nv_users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_tasks (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      url TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 5,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_task_completions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES nv_users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL REFERENCES nv_tasks(id) ON DELETE CASCADE,
      points_awarded INTEGER NOT NULL DEFAULT 0,
      completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, task_id)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_checkins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES nv_users(id) ON DELETE CASCADE,
      checkin_date DATE NOT NULL,
      points_awarded INTEGER NOT NULL DEFAULT 10,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, checkin_date)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_rewards (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      cost INTEGER NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS nv_redemptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES nv_users(id) ON DELETE CASCADE,
      reward_id INTEGER NOT NULL REFERENCES nv_rewards(id),
      reward_title TEXT NOT NULL,
      cost INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      processed_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nv_sessions_user_idx
    ON nv_sessions(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nv_tasks_active_idx
    ON nv_tasks(active);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nv_completions_user_idx
    ON nv_task_completions(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nv_checkins_user_idx
    ON nv_checkins(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nv_redemptions_user_idx
    ON nv_redemptions(user_id);
  `);

  const taskCount = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM nv_tasks
  `);

  if (taskCount.rows[0].count === 0) {
    await pool.query(
      `
        INSERT INTO nv_tasks
        (title, description, url, points)
        VALUES
        ($1, $2, $3, $4),
        ($5, $6, $7, $8),
        ($9, $10, $11, $12)
      `,
      [
        "Theo dõi kênh TikTok chính",
        "Mở TikTok và thực hiện nhiệm vụ thủ công.",
        "https://www.tiktok.com/@uyn.uyn2229",
        10,

        "Khám phá kênh cộng đồng",
        "Mở kênh và thực hiện nhiệm vụ nếu bạn muốn.",
        "https://www.tiktok.com/",
        5,

        "Xem nội dung đề xuất",
        "Khám phá nội dung TikTok.",
        "https://www.tiktok.com/",
        5
      ]
    );
  }

  const rewardCount = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM nv_rewards
  `);

  if (rewardCount.rows[0].count === 0) {
    await pool.query(
      `
        INSERT INTO nv_rewards
        (title, description, cost)
        VALUES
        ($1, $2, $3),
        ($4, $5, $6),
        ($7, $8, $9)
      `,
      [
        "Gói 50 điểm",
        "Đổi điểm theo quy định của hệ thống.",
        50,

        "Gói 100 điểm",
        "Đổi điểm theo quy định của hệ thống.",
        100,

        "Gói 250 điểm",
        "Đổi điểm theo quy định của hệ thống.",
        250
      ]
    );
  }

  console.log("PostgreSQL initialized successfully.");
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    return ok(res, {
      status: "online",
      database: "connected"
    });
  } catch (error) {
    console.error("HEALTH ERROR:", error);

    return res.status(500).json({
      success: false,
      status: "offline",
      database: "error"
    });
  }
});

/* =========================================================
   AUTH - REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const username = cleanUsername(req.body.username);
    const referralCode = String(req.body.referralCode || "")
      .trim()
      .toUpperCase();

    if (!validEmail(email)) {
      return fail(res, 400, "Email không hợp lệ.");
    }

    if (password.length < 6) {
      return fail(res, 400, "Mật khẩu phải có ít nhất 6 ký tự.");
    }

    if (username.length < 2) {
      return fail(res, 400, "Tên người dùng phải có ít nhất 2 ký tự.");
    }

    const existing = await pool.query(
      `
        SELECT id
        FROM nv_users
        WHERE email = $1
        LIMIT 1
      `,
      [email]
    );

    if (existing.rows.length > 0) {
      return fail(res, 409, "Email này đã được đăng ký.");
    }

    let referrer = null;

    if (referralCode) {
      const refResult = await pool.query(
        `
          SELECT id
          FROM nv_users
          WHERE referral_code = $1
          LIMIT 1
        `,
        [referralCode]
      );

      if (refResult.rows.length === 0) {
        return fail(res, 400, "Mã giới thiệu không tồn tại.");
      }

      referrer = refResult.rows[0];
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let newReferralCode;

    for (let i = 0; i < 10; i++) {
      const candidate =
        username
          .replace(/[^a-zA-Z0-9]/g, "")
          .slice(0, 6)
          .toUpperCase() +
        crypto.randomBytes(3).toString("hex").toUpperCase();

      const check = await pool.query(
        `
          SELECT id
          FROM nv_users
          WHERE referral_code = $1
          LIMIT 1
        `,
        [candidate]
      );

      if (check.rows.length === 0) {
        newReferralCode = candidate;
        break;
      }
    }

    if (!newReferralCode) {
      newReferralCode = crypto
        .randomBytes(6)
        .toString("hex")
        .toUpperCase();
    }

    const role =
      ADMIN_EMAIL && email === ADMIN_EMAIL
        ? "admin"
        : "user";

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const userResult = await client.query(
        `
          INSERT INTO nv_users
          (
            email,
            username,
            password_hash,
            role,
            points,
            referral_code,
            referred_by
          )
          VALUES
          ($1, $2, $3, $4, $5, $6, $7)
          RETURNING
            id,
            email,
            username,
            role,
            points,
            referral_code
        `,
        [
          email,
          username,
          passwordHash,
          role,
          referrer ? 10 : 0,
          newReferralCode,
          referrer ? referrer.id : null
        ]
      );

      const user = userResult.rows[0];

      if (referrer) {
        await client.query(
          `
            UPDATE nv_users
            SET points = points + 20
            WHERE id = $1
          `,
          [referrer.id]
        );
      }

      await client.query("COMMIT");

      const token = await createSession(user.id);
      setSessionCookie(res, token);

      return ok(res, {
        message: "Đăng ký thành công.",
        user
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    if (error.code === "23505") {
      return fail(res, 409, "Email hoặc mã giới thiệu đã tồn tại.");
    }

    return fail(res, 500, "Đăng ký thất bại. Vui lòng thử lại.");
  }
});

/* =========================================================
   AUTH - LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!validEmail(email)) {
      return fail(res, 400, "Email không hợp lệ.");
    }

    if (!password) {
      return fail(res, 400, "Vui lòng nhập mật khẩu.");
    }

    const result = await pool.query(
      `
        SELECT *
        FROM nv_users
        WHERE email = $1
        LIMIT 1
      `,
      [email]
    );

    if (result.rows.length === 0) {
      return fail(res, 401, "Email hoặc mật khẩu không đúng.");
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return fail(res, 401, "Email hoặc mật khẩu không đúng.");
    }

    const token = await createSession(user.id);

    setSessionCookie(res, token);

    delete user.password_hash;

    return ok(res, {
      message: "Đăng nhập thành công.",
      user
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return fail(res, 500, "Đăng nhập thất bại.");
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", async (req, res) => {
  try {
    const rawToken = getCookie(req, "nv_session");

    if (rawToken) {
      await pool.query(
        `
          DELETE FROM nv_sessions
          WHERE token_hash = $1
        `,
        [hashToken(rawToken)]
      );
    }

    clearSessionCookie(res);

    return ok(res, {
      message: "Đã đăng xuất."
    });
  } catch (error) {
    console.error("LOGOUT ERROR:", error);

    clearSessionCookie(res);

    return ok(res);
  }
});

/* =========================================================
   ME
========================================================= */

app.get("/api/me", auth, async (req, res) => {
  return ok(res, {
    user: req.user
  });
});

/* =========================================================
   CHECK-IN
========================================================= */

app.post("/api/checkin", auth, async (req, res) => {
  try {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const check = await client.query(
        `
          SELECT id
          FROM nv_checkins
          WHERE user_id = $1
            AND checkin_date = CURRENT_DATE
          LIMIT 1
        `,
        [req.user.id]
      );

      if (check.rows.length > 0) {
        await client.query("ROLLBACK");

        return fail(
          res,
          400,
          "Hôm nay bạn đã điểm danh rồi."
        );
      }

      const last = await client.query(
        `
          SELECT last_checkin
          FROM nv_users
          WHERE id = $1
          FOR UPDATE
        `,
        [req.user.id]
      );

      let newStreak = 1;

      if (last.rows[0].last_checkin) {
        const yesterday = await client.query(`
          SELECT CURRENT_DATE - INTERVAL '1 day' AS date
        `);

        const yesterdayDate =
          yesterday.rows[0].date;

        const lastDate =
          new Date(
            last.rows[0].last_checkin
          ).toISOString().slice(0, 10);

        const yDate =
          new Date(
            yesterdayDate
          ).toISOString().slice(0, 10);

        if (lastDate === yDate) {
          newStreak = Number(req.user.streak || 0) + 1;
        }
      }

      await client.query(
        `
          INSERT INTO nv_checkins
          (user_id, checkin_date, points_awarded)
          VALUES ($1, CURRENT_DATE, 10)
        `,
        [req.user.id]
      );

      await client.query(
        `
          UPDATE nv_users
          SET
            points = points + 10,
            total_checkins = total_checkins + 1,
            streak = $2,
            last_checkin = CURRENT_DATE
          WHERE id = $1
        `,
        [req.user.id, newStreak]
      );

      await client.query("COMMIT");

      return ok(res, {
        message: "Điểm danh thành công +10 điểm.",
        pointsAdded: 10,
        streak: newStreak
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("CHECKIN ERROR:", error);

    return fail(res, 500, "Điểm danh thất bại.");
  }
});

/* =========================================================
   TASKS
========================================================= */

app.get("/api/tasks", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          t.id,
          t.title,
          t.description,
          t.url,
          t.points,
          t.created_at,
          CASE
            WHEN c.id IS NULL THEN FALSE
            ELSE TRUE
          END AS completed
        FROM nv_tasks t
        LEFT JOIN nv_task_completions c
          ON c.task_id = t.id
         AND c.user_id = $1
        WHERE t.active = TRUE
        ORDER BY RANDOM()
        LIMIT 20
      `,
      [req.user.id]
    );

    return ok(res, {
      tasks: result.rows
    });
  } catch (error) {
    console.error("TASK LIST ERROR:", error);

    return fail(res, 500, "Không tải được nhiệm vụ.");
  }
});

app.post("/api/tasks/:id/complete", auth, async (req, res) => {
  const taskId = Number(req.params.id);

  if (!Number.isInteger(taskId)) {
    return fail(res, 400, "Nhiệm vụ không hợp lệ.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const taskResult = await client.query(
      `
        SELECT id, points, active
        FROM nv_tasks
        WHERE id = $1
        FOR UPDATE
      `,
      [taskId]
    );

    if (taskResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return fail(res, 404, "Không tìm thấy nhiệm vụ.");
    }

    const task = taskResult.rows[0];

    if (!task.active) {
      await client.query("ROLLBACK");
      return fail(res, 400, "Nhiệm vụ đã tạm dừng.");
    }

    const existing = await client.query(
      `
        SELECT id
        FROM nv_task_completions
        WHERE user_id = $1
          AND task_id = $2
        LIMIT 1
      `,
      [req.user.id, taskId]
    );

    if (existing.rows.length > 0) {
      await client.query("ROLLBACK");

      return fail(
        res,
        400,
        "Bạn đã hoàn thành nhiệm vụ này."
      );
    }

    await client.query(
      `
        INSERT INTO nv_task_completions
        (user_id, task_id, points_awarded)
        VALUES ($1, $2, $3)
      `,
      [req.user.id, taskId, task.points]
    );

    await client.query(
      `
        UPDATE nv_users
        SET
          points = points + $2,
          total_completed = total_completed + 1
        WHERE id = $1
      `,
      [req.user.id, task.points]
    );

    await client.query("COMMIT");

    return ok(res, {
      message: `Hoàn thành nhiệm vụ +${task.points} điểm.`,
      pointsAdded: task.points
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error("TASK COMPLETE ERROR:", error);

    return fail(res, 500, "Không thể hoàn thành nhiệm vụ.");
  } finally {
    client.release();
  }
});

/* =========================================================
   LEADERBOARD
========================================================= */

app.get("/api/leaderboard/day", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.username,
        u.points,
        COALESCE(
          (
            SELECT SUM(c.points_awarded)
            FROM nv_task_completions c
            WHERE c.user_id = u.id
              AND c.completed_at >= CURRENT_DATE
          ),
          0
        )
        +
        COALESCE(
          (
            SELECT SUM(ci.points_awarded)
            FROM nv_checkins ci
            WHERE ci.user_id = u.id
              AND ci.checkin_date = CURRENT_DATE
          ),
          0
        ) AS today_points
      FROM nv_users u
      ORDER BY today_points DESC, u.id ASC
      LIMIT 50
    `);

    return ok(res, {
      reward: {
        1: 50,
        2: 30,
        3: 20
      },
      leaderboard: result.rows
    });
  } catch (error) {
    console.error("DAY LEADERBOARD ERROR:", error);

    return fail(res, 500, "Không tải được bảng xếp hạng.");
  }
});

app.get("/api/leaderboard/week", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.username,
        u.points,
        COALESCE(
          (
            SELECT SUM(c.points_awarded)
            FROM nv_task_completions c
            WHERE c.user_id = u.id
              AND c.completed_at >= date_trunc('week', CURRENT_DATE)
          ),
          0
        )
        +
        COALESCE(
          (
            SELECT SUM(ci.points_awarded)
            FROM nv_checkins ci
            WHERE ci.user_id = u.id
              AND ci.checkin_date >= date_trunc('week', CURRENT_DATE)::date
          ),
          0
        ) AS week_points
      FROM nv_users u
      ORDER BY week_points DESC, u.id ASC
      LIMIT 50
    `);

    return ok(res, {
      reward: {
        1: 150,
        2: 100,
        3: 50
      },
      leaderboard: result.rows
    });
  } catch (error) {
    console.error("WEEK LEADERBOARD ERROR:", error);

    return fail(res, 500, "Không tải được bảng xếp hạng.");
  }
});

/* =========================================================
   REFERRAL
========================================================= */

app.get("/api/referral", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          referral_code,
          COUNT(*) FILTER (
            WHERE referred_by = $1
          )::int AS invited_users
        FROM nv_users
        WHERE id = $1
        GROUP BY referral_code
      `,
      [req.user.id]
    );

    return ok(res, {
      referralCode: result.rows[0]?.referral_code || "",
      invitedUsers: result.rows[0]?.invited_users || 0,
      rewardForInviter: 20,
      rewardForNewUser: 10
    });
  } catch (error) {
    console.error("REFERRAL ERROR:", error);

    return fail(res, 500, "Không tải được thông tin giới thiệu.");
  }
});

/* =========================================================
   REWARDS
========================================================= */

app.get("/api/rewards", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        title,
        description,
        cost
      FROM nv_rewards
      WHERE active = TRUE
      ORDER BY cost ASC
    `);

    return ok(res, {
      rewards: result.rows
    });
  } catch (error) {
    console.error("REWARDS ERROR:", error);

    return fail(res, 500, "Không tải được phần đổi điểm.");
  }
});

app.post("/api/rewards/:id/redeem", auth, async (req, res) => {
  const rewardId = Number(req.params.id);

  if (!Number.isInteger(rewardId)) {
    return fail(res, 400, "Gói đổi điểm không hợp lệ.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const rewardResult = await client.query(
      `
        SELECT id, title, cost
        FROM nv_rewards
        WHERE id = $1
          AND active = TRUE
        FOR UPDATE
      `,
      [rewardId]
    );

    if (rewardResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return fail(res, 404, "Không tìm thấy phần thưởng.");
    }

    const reward = rewardResult.rows[0];

    const userResult = await client.query(
      `
        SELECT points
        FROM nv_users
        WHERE id = $1
        FOR UPDATE
      `,
      [req.user.id]
    );

    const currentPoints = userResult.rows[0].points;

    if (currentPoints < reward.cost) {
      await client.query("ROLLBACK");

      return fail(
        res,
        400,
        "Bạn không đủ điểm để đổi."
      );
    }

    await client.query(
      `
        UPDATE nv_users
        SET points = points - $2
        WHERE id = $1
      `,
      [req.user.id, reward.cost]
    );

    const redemption = await client.query(
      `
        INSERT INTO nv_redemptions
        (
          user_id,
          reward_id,
          reward_title,
          cost,
          status
        )
        VALUES
        ($1, $2, $3, $4, 'pending')
        RETURNING id, status, created_at
      `,
      [
        req.user.id,
        reward.id,
        reward.title,
        reward.cost
      ]
    );

    await client.query("COMMIT");

    return ok(res, {
      message: "Đã tạo yêu cầu đổi điểm.",
      redemption: redemption.rows[0],
      remainingPoints: currentPoints - reward.cost
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error("REDEEM ERROR:", error);

    return fail(res, 500, "Đổi điểm thất bại.");
  } finally {
    client.release();
  }
});

/* =========================================================
   USER REDEMPTIONS
========================================================= */

app.get("/api/redemptions", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          id,
          reward_title,
          cost,
          status,
          created_at,
          processed_at
        FROM nv_redemptions
        WHERE user_id = $1
        ORDER BY id DESC
        LIMIT 50
      `,
      [req.user.id]
    );

    return ok(res, {
      redemptions: result.rows
    });
  } catch (error) {
    console.error("USER REDEMPTIONS ERROR:", error);

    return fail(res, 500, "Không tải được lịch sử đổi điểm.");
  }
});

/* =========================================================
   ADMIN - USERS
========================================================= */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          email,
          username,
          role,
          points,
          total_completed,
          total_checkins,
          streak,
          referral_code,
          created_at
        FROM nv_users
        ORDER BY id DESC
        LIMIT 200
      `);

      return ok(res, {
        users: result.rows
      });
    } catch (error) {
      console.error("ADMIN USERS ERROR:", error);

      return fail(res, 500, "Không tải được người dùng.");
    }
  }
);

/* =========================================================
   ADMIN - TASKS
========================================================= */

app.get(
  "/api/admin/tasks",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT *
        FROM nv_tasks
        ORDER BY id DESC
      `);

      return ok(res, {
        tasks: result.rows
      });
    } catch (error) {
      console.error("ADMIN TASKS ERROR:", error);

      return fail(res, 500, "Không tải được nhiệm vụ.");
    }
  }
);

app.post(
  "/api/admin/tasks",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const title = String(req.body.title || "").trim();
      const description = String(
        req.body.description || ""
      ).trim();
      const url = String(req.body.url || "").trim();
      const points = Number(req.body.points);

      if (!title) {
        return fail(res, 400, "Thiếu tên nhiệm vụ.");
      }

      if (!url || !/^https?:\/\//i.test(url)) {
        return fail(res, 400, "URL không hợp lệ.");
      }

      if (!Number.isInteger(points) || points < 1 || points > 1000) {
        return fail(res, 400, "Điểm nhiệm vụ không hợp lệ.");
      }

      const result = await pool.query(
        `
          INSERT INTO nv_tasks
          (title, description, url, points)
          VALUES ($1, $2, $3, $4)
          RETURNING *
        `,
        [
          title,
          description,
          url,
          points
        ]
      );

      return ok(res, {
        message: "Đã tạo nhiệm vụ.",
        task: result.rows[0]
      });
    } catch (error) {
      console.error("ADMIN CREATE TASK ERROR:", error);

      return fail(res, 500, "Không tạo được nhiệm vụ.");
    }
  }
);

app.patch(
  "/api/admin/tasks/:id",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const taskId = Number(req.params.id);

      if (!Number.isInteger(taskId)) {
        return fail(res, 400, "ID nhiệm vụ không hợp lệ.");
      }

      const active =
        req.body.active === true ||
        req.body.active === "true";

      const result = await pool.query(
        `
          UPDATE nv_tasks
          SET active = $2
          WHERE id = $1
          RETURNING *
        `,
        [taskId, active]
      );

      if (result.rows.length === 0) {
        return fail(res, 404, "Không tìm thấy nhiệm vụ.");
      }

      return ok(res, {
        message: "Đã cập nhật nhiệm vụ.",
        task: result.rows[0]
      });
    } catch (error) {
      console.error("ADMIN UPDATE TASK ERROR:", error);

      return fail(res, 500, "Không cập nhật được nhiệm vụ.");
    }
  }
);

/* =========================================================
   ADMIN - REDEMPTIONS
========================================================= */

app.get(
  "/api/admin/redemptions",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          r.id,
          r.user_id,
          u.username,
          u.email,
          r.reward_title,
          r.cost,
          r.status,
          r.created_at,
          r.processed_at
        FROM nv_redemptions r
        JOIN nv_users u
          ON u.id = r.user_id
        ORDER BY r.id DESC
        LIMIT 200
      `);

      return ok(res, {
        redemptions: result.rows
      });
    } catch (error) {
      console.error("ADMIN REDEMPTIONS ERROR:", error);

      return fail(res, 500, "Không tải được yêu cầu đổi điểm.");
    }
  }
);

app.patch(
  "/api/admin/redemptions/:id",
  auth,
  adminOnly,
  async (req, res) => {
    const redemptionId = Number(req.params.id);
    const status = String(req.body.status || "")
      .trim()
      .toLowerCase();

    const allowed = [
      "pending",
      "approved",
      "done",
      "rejected"
    ];

    if (!Number.isInteger(redemptionId)) {
      return fail(res, 400, "ID yêu cầu không hợp lệ.");
    }

    if (!allowed.includes(status)) {
      return fail(res, 400, "Trạng thái không hợp lệ.");
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `
          SELECT *
          FROM nv_redemptions
          WHERE id = $1
          FOR UPDATE
        `,
        [redemptionId]
      );

      if (result.rows.length === 0) {
        await client.query("ROLLBACK");

        return fail(res, 404, "Không tìm thấy yêu cầu.");
      }

      const redemption = result.rows[0];

      if (
        redemption.status === "rejected" ||
        redemption.status === "done"
      ) {
        await client.query("ROLLBACK");

        return fail(
          res,
          400,
          "Yêu cầu này đã được xử lý."
        );
      }

      if (status === "rejected") {
        await client.query(
          `
            UPDATE nv_users
            SET points = points + $2
            WHERE id = $1
          `,
          [
            redemption.user_id,
            redemption.cost
          ]
        );
      }

      await client.query(
        `
          UPDATE nv_redemptions
          SET
            status = $2,
            processed_at =
              CASE
                WHEN $2 IN ('approved', 'done', 'rejected')
                THEN NOW()
                ELSE processed_at
              END
          WHERE id = $1
        `,
        [
          redemptionId,
          status
        ]
      );

      await client.query("COMMIT");

      return ok(res, {
        message: "Đã cập nhật yêu cầu."
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "ADMIN UPDATE REDEMPTION ERROR:",
        error
      );

      return fail(
        res,
        500,
        "Không cập nhật được yêu cầu."
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   CLEAN OLD SESSIONS
========================================================= */

async function cleanSessions() {
  try {
    await pool.query(`
      DELETE FROM nv_sessions
      WHERE expires_at <= NOW()
    `);
  } catch (error) {
    console.error("SESSION CLEAN ERROR:", error);
  }
}

/* =========================================================
   FRONTEND
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(INDEX_FILE);
});

/*
  Regex route được dùng thay cho app.get("*")
  để tránh khác biệt giữa các phiên bản router.
*/
app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return next();
  }

  res.sendFile(INDEX_FILE, (error) => {
    if (error) {
      next(error);
    }
  });
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      success: false,
      message: "API không tồn tại."
    });
  }

  return res.status(404).send("404 - Page not found");
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    success: false,
    message: "Lỗi máy chủ.",
    error:
      process.env.NODE_ENV === "production"
        ? undefined
        : error.message
  });
});

/* =========================================================
   START
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    await cleanSessions();

    setInterval(
      cleanSessions,
      60 * 60 * 1000
    );

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `NhiemVuTikTokFree running on port ${PORT}`
      );
      console.log(
        `Public directory: ${PUBLIC_DIR}`
      );
      console.log(
        `Index file: ${INDEX_FILE}`
      );
    });
  } catch (error) {
    console.error("STARTUP ERROR:", error);
    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  console.log("SIGTERM received.");
  await pool.end();
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received.");
  await pool.end();
  process.exit(0);
});

startServer();
