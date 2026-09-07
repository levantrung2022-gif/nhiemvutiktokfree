const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL chưa được cấu hình.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

const sessions = new Map();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Bạn cần đăng nhập."
    });
  }

  const token = header.substring(7);
  const session = sessions.get(token);

  if (!session) {
    return res.status(401).json({
      error: "Phiên đăng nhập đã hết hạn."
    });
  }

  req.user = session;
  req.token = token;
  next();
}

function isAdmin(req) {
  return (
    process.env.ADMIN_EMAIL &&
    req.user.email.toLowerCase() ===
      process.env.ADMIN_EMAIL.toLowerCase()
  );
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 0,
      checkin_streak INTEGER NOT NULL DEFAULT 0,
      last_checkin DATE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      channel VARCHAR(255) NOT NULL,
      url TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 5,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS task_opens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      opened_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS task_completions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      points INTEGER NOT NULL,
      completed_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_checkins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      checkin_date DATE NOT NULL,
      points INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, checkin_date)
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_task_completions_user_date
    ON task_completions(user_id, completed_at)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_daily_checkins_user_date
    ON daily_checkins(user_id, checkin_date)
  `);

  const count = await pool.query(`
    SELECT COUNT(*)::int AS count FROM tasks
  `);

  if (count.rows[0].count === 0) {
    const tasks = [
      ["Khám phá kênh TikTok", "@maclaxinh1601", "https://www.tiktok.com/@maclaxinh1601", 5],
      ["Khám phá kênh chính", "@uyn.uyn2229", "https://www.tiktok.com/@uyn.uyn2229", 5],
      ["Khám phá kênh TikTok", "@thuychang612003", "https://www.tiktok.com/@thuychang612003", 5],
      ["Khám phá kênh TikTok", "@jang.1.4.6", "https://www.tiktok.com/@jang.1.4.6", 5],
      ["Khám phá kênh TikTok", "@ngocnhu_png", "https://www.tiktok.com/@ngocnhu_png", 5],
      ["Khám phá kênh TikTok", "@thao.vo221", "https://www.tiktok.com/@thao.vo221", 5],
      ["Khám phá kênh TikTok", "@vaycongsono1", "https://www.tiktok.com/@vaycongsono1", 5],
      ["Khám phá kênh TikTok", "@.trang5689", "https://www.tiktok.com/@.trang5689", 5]
    ];

    for (const task of tasks) {
      await pool.query(
        `
        INSERT INTO tasks
        (title, channel, url, points)
        VALUES ($1, $2, $3, $4)
        `,
        task
      );
    }
  }
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name) {
      return res.status(400).json({
        error: "Vui lòng nhập tên."
      });
    }

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        error: "Email không hợp lệ."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Mật khẩu phải có ít nhất 6 ký tự."
      });
    }

    const exists = await pool.query(
      `SELECT id FROM users WHERE email = $1`,
      [email]
    );

    if (exists.rowCount) {
      return res.status(409).json({
        error: "Email này đã được đăng ký."
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (name, email, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, name, email, points, checkin_streak
      `,
      [name, email, passwordHash]
    );

    const user = result.rows[0];
    const token = createToken();

    sessions.set(token, {
      id: user.id,
      name: user.name,
      email: user.email
    });

    res.json({
      token,
      user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể tạo tài khoản."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const result = await pool.query(
      `
      SELECT id, name, email, password_hash
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Email hoặc mật khẩu không đúng."
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Email hoặc mật khẩu không đúng."
      });
    }

    const token = createToken();

    sessions.set(token, {
      id: user.id,
      name: user.name,
      email: user.email
    });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể đăng nhập."
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", auth, (req, res) => {
  sessions.delete(req.token);

  res.json({
    ok: true
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        u.id,
        u.name,
        u.email,
        u.points,
        u.checkin_streak,
        u.last_checkin,

        (
          SELECT COUNT(*)::int
          FROM task_completions tc
          WHERE tc.user_id = u.id
        ) AS completed,

        (
          SELECT COUNT(*)::int
          FROM task_opens to2
          WHERE to2.user_id = u.id
        ) AS opened,

        (
          SELECT COUNT(*)::int
          FROM daily_checkins dc
          WHERE dc.user_id = u.id
        ) AS total_checkins

      FROM users u
      WHERE u.id = $1
      `,
      [req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Không tìm thấy tài khoản."
      });
    }

    res.json({
      user: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể tải thông tin tài khoản."
    });
  }
});

/* =========================
   DAILY CHECK-IN
========================= */

app.get("/api/checkin/status", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        CURRENT_DATE AS today,
        EXISTS(
          SELECT 1
          FROM daily_checkins
          WHERE user_id = $1
          AND checkin_date = CURRENT_DATE
        ) AS checked_in
      `,
      [req.user.id]
    );

    const user = await pool.query(
      `
      SELECT
        checkin_streak,
        last_checkin
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    res.json({
      today: result.rows[0].today,
      checkedIn: result.rows[0].checked_in,
      streak: user.rows[0]?.checkin_streak || 0,
      lastCheckin: user.rows[0]?.last_checkin || null
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể kiểm tra điểm danh."
    });
  }
});

app.post("/api/checkin", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const userResult = await client.query(
      `
      SELECT
        id,
        checkin_streak,
        last_checkin
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.id]
    );

    if (!userResult.rowCount) {
      throw new Error("Không tìm thấy tài khoản.");
    }

    const user = userResult.rows[0];

    const already = await client.query(
      `
      SELECT id
      FROM daily_checkins
      WHERE user_id = $1
      AND checkin_date = CURRENT_DATE
      `,
      [req.user.id]
    );

    if (already.rowCount) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "Hôm nay bạn đã điểm danh rồi."
      });
    }

    let streak = Number(user.checkin_streak || 0);

    if (user.last_checkin) {
      const dateResult = await client.query(`
        SELECT
          CURRENT_DATE - $1::date AS days
      `, [user.last_checkin]);

      const days = Number(dateResult.rows[0].days);

      if (days === 1) {
        streak += 1;
      } else {
        streak = 1;
      }
    } else {
      streak = 1;
    }

    /*
      Điểm danh cơ bản:
      - Mỗi ngày +10 điểm
      - Chuỗi từ 7 ngày trở lên vẫn +10,
        không cộng quá nhiều điểm tự động.
    */

    const checkinPoints = 10;

    await client.query(
      `
      INSERT INTO daily_checkins
      (user_id, checkin_date, points)
      VALUES ($1, CURRENT_DATE, $2)
      `,
      [req.user.id, checkinPoints]
    );

    await client.query(
      `
      UPDATE users
      SET
        points = points + $1,
        checkin_streak = $2,
        last_checkin = CURRENT_DATE
      WHERE id = $3
      `,
      [
        checkinPoints,
        streak,
        req.user.id
      ]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      points: checkinPoints,
      streak
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Không thể điểm danh."
    });
  } finally {
    client.release();
  }
});

/* =========================
   RANDOM TASK
========================= */

app.get("/api/tasks/random", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        title,
        channel,
        url,
        points
      FROM tasks
      WHERE active = TRUE
      ORDER BY RANDOM()
      LIMIT 1
    `);

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Hiện chưa có nhiệm vụ."
      });
    }

    res.json({
      task: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể lấy nhiệm vụ."
    });
  }
});

/* =========================
   OPEN TASK
========================= */

app.post("/api/tasks/:id/open", auth, async (req, res) => {
  try {
    const taskId = Number(req.params.id);

    const task = await pool.query(
      `
      SELECT id
      FROM tasks
      WHERE id = $1
      AND active = TRUE
      `,
      [taskId]
    );

    if (!task.rowCount) {
      return res.status(404).json({
        error: "Nhiệm vụ không tồn tại."
      });
    }

    await pool.query(
      `
      INSERT INTO task_opens
      (user_id, task_id)
      VALUES ($1, $2)
      `,
      [req.user.id, taskId]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể ghi nhận lượt mở."
    });
  }
});

/* =========================
   COMPLETE TASK
========================= */

app.post("/api/tasks/:id/complete", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const taskId = Number(req.params.id);

    const taskResult = await client.query(
      `
      SELECT
        id,
        points,
        active
      FROM tasks
      WHERE id = $1
      FOR UPDATE
      `,
      [taskId]
    );

    if (!taskResult.rowCount || !taskResult.rows[0].active) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Nhiệm vụ không tồn tại hoặc đã tắt."
      });
    }

    const task = taskResult.rows[0];

    const duplicate = await client.query(
      `
      SELECT id
      FROM task_completions
      WHERE user_id = $1
      AND task_id = $2
      AND completed_at::date = CURRENT_DATE
      LIMIT 1
      `,
      [
        req.user.id,
        taskId
      ]
    );

    if (duplicate.rowCount) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "Bạn đã hoàn thành nhiệm vụ này hôm nay rồi."
      });
    }

    const points = Number(task.points);

    await client.query(
      `
      INSERT INTO task_completions
      (user_id, task_id, points)
      VALUES ($1, $2, $3)
      `,
      [
        req.user.id,
        taskId,
        points
      ]
    );

    await client.query(
      `
      UPDATE users
      SET points = points + $1
      WHERE id = $2
      `,
      [
        points,
        req.user.id
      ]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      points
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Không thể hoàn thành nhiệm vụ."
    });
  } finally {
    client.release();
  }
});

/* =========================
   LEADERBOARD
========================= */

app.get("/api/leaderboard/day", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.name,
        u.email,
        COALESCE(SUM(tc.points), 0)::int AS points
      FROM users u
      LEFT JOIN task_completions tc
        ON tc.user_id = u.id
        AND tc.completed_at::date = CURRENT_DATE
      GROUP BY u.id
      ORDER BY points DESC, u.id ASC
      LIMIT 50
    `);

    res.json({
      period: "day",
      leaderboard: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể tải bảng xếp hạng ngày."
    });
  }
});

app.get("/api/leaderboard/week", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.name,
        u.email,
        COALESCE(SUM(tc.points), 0)::int AS points
      FROM users u
      LEFT JOIN task_completions tc
        ON tc.user_id = u.id
        AND tc.completed_at >= date_trunc('week', CURRENT_DATE)
      GROUP BY u.id
      ORDER BY points DESC, u.id ASC
      LIMIT 50
    `);

    res.json({
      period: "week",
      leaderboard: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể tải bảng xếp hạng tuần."
    });
  }
});

/* =========================
   ADMIN TASKS
========================= */

app.get("/api/admin/tasks", auth, async (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({
      error: "Bạn không có quyền quản trị."
    });
  }

  try {
    const result = await pool.query(`
      SELECT
        id,
        title,
        channel,
        url,
        points,
        active,
        created_at
      FROM tasks
      ORDER BY id DESC
    `);

    res.json({
      tasks: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể tải nhiệm vụ."
    });
  }
});

app.post("/api/admin/tasks", auth, async (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({
      error: "Bạn không có quyền quản trị."
    });
  }

  try {
    const title = String(req.body.title || "").trim();
    const channel = String(req.body.channel || "").trim();
    const url = String(req.body.url || "").trim();
    const points = Number(req.body.points || 5);

    if (!title || !channel || !url) {
      return res.status(400).json({
        error: "Vui lòng nhập đủ thông tin."
      });
    }

    if (!Number.isInteger(points) || points < 1) {
      return res.status(400).json({
        error: "Điểm nhiệm vụ không hợp lệ."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO tasks
      (title, channel, url, points)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        title,
        channel,
        url,
        points
      ]
    );

    res.json({
      ok: true,
      task: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể thêm nhiệm vụ."
    });
  }
});

app.delete("/api/admin/tasks/:id", auth, async (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({
      error: "Bạn không có quyền quản trị."
    });
  }

  try {
    const taskId = Number(req.params.id);

    const result = await pool.query(
      `
      UPDATE tasks
      SET active = FALSE
      WHERE id = $1
      RETURNING id
      `,
      [taskId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Không tìm thấy nhiệm vụ."
      });
    }

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không thể tắt nhiệm vụ."
    });
  }
});

/* =========================
   FRONTEND FALLBACK
========================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================
   START SERVER
========================= */

async function start() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `nhiemvutiktokfree đang chạy tại port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Không thể khởi động server:",
      error
    );

    process.exit(1);
  }
}

start();
