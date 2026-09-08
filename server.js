const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");

if (!DATABASE_URL) {
  console.error("STARTUP ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const publicDir = path.join(__dirname, "public");

app.use(express.static(publicDir));

const sessions = new Map();

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function createReferralCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validTikTokUrl(value) {
  try {
    const url = new URL(String(value || "").trim());

    return (
      url.protocol === "https:" &&
      (
        url.hostname === "tiktok.com" ||
        url.hostname.endsWith(".tiktok.com")
      )
    );
  } catch {
    return false;
  }
}

function auth(req, res, next) {
  const header = String(req.headers.authorization || "");

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Chưa đăng nhập."
    });
  }

  const token = header.slice(7).trim();
  const session = sessions.get(token);

  if (!session) {
    return res.status(401).json({
      error: "Phiên đăng nhập không hợp lệ."
    });
  }

  if (session.expiresAt < Date.now()) {
    sessions.delete(token);

    return res.status(401).json({
      error: "Phiên đăng nhập đã hết hạn."
    });
  }

  req.user = session.user;
  req.token = token;

  next();
}

function adminOnly(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({
      error: "Bạn không có quyền quản trị."
    });
  }

  next();
}

async function transaction(callback) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await callback(client);

    await client.query("COMMIT");

    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function addPoints(client, userId, amount, reason) {
  await client.query(
    `
    UPDATE users
    SET points = points + $1
    WHERE id = $2
    `,
    [amount, userId]
  );

  await client.query(
    `
    INSERT INTO point_transactions
    (user_id, amount, reason)
    VALUES ($1, $2, $3)
    `,
    [userId, amount, reason]
  );
}

async function removePoints(client, userId, amount, reason) {
  const result = await client.query(
    `
    UPDATE users
    SET points = points - $1
    WHERE id = $2
      AND points >= $1
    RETURNING id
    `,
    [amount, userId]
  );

  if (!result.rowCount) {
    throw new Error("Không đủ điểm.");
  }

  await client.query(
    `
    INSERT INTO point_transactions
    (user_id, amount, reason)
    VALUES ($1, $2, $3)
    `,
    [userId, -amount, reason]
  );
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    points: user.points,
    referral_code: user.referral_code,
    is_admin: user.is_admin,
    is_blocked: user.is_blocked
  };
}

async function createSession(user) {
  const token = createToken();

  sessions.set(token, {
    user: publicUser(user),
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
  });

  return token;
}

async function initDatabase() {
  console.log("Initializing database...");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 0,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL DEFAULT 'Nhiệm vụ TikTok',
      description TEXT NOT NULL DEFAULT '',
      task_url TEXT NOT NULL DEFAULT '',
      points INTEGER NOT NULL DEFAULT 10,
      is_main BOOLEAN NOT NULL DEFAULT FALSE,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
   * Sửa database cũ nếu bảng tasks đã tồn tại
   * nhưng thiếu các cột của phiên bản mới.
   */

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS title TEXT;
  `);

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS description TEXT;
  `);

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS task_url TEXT;
  `);

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS points INTEGER;
  `);

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS is_main BOOLEAN;
  `);

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS active BOOLEAN;
  `);

  await pool.query(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
  `);

  await pool.query(`
    UPDATE tasks
    SET title = 'Nhiệm vụ TikTok'
    WHERE title IS NULL;
  `);

  await pool.query(`
    UPDATE tasks
    SET description = ''
    WHERE description IS NULL;
  `);

  await pool.query(`
    UPDATE tasks
    SET task_url = ''
    WHERE task_url IS NULL;
  `);

  await pool.query(`
    UPDATE tasks
    SET points = 10
    WHERE points IS NULL;
  `);

  await pool.query(`
    UPDATE tasks
    SET is_main = FALSE
    WHERE is_main IS NULL;
  `);

  await pool.query(`
    UPDATE tasks
    SET active = TRUE
    WHERE active IS NULL;
  `);

  await pool.query(`
    UPDATE tasks
    SET created_at = NOW()
    WHERE created_at IS NULL;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS task_completions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, task_id)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS checkins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      checkin_date DATE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, checkin_date)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS point_transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS packages (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      points INTEGER NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS promotions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      package_name TEXT NOT NULL,
      points INTEGER NOT NULL,
      tiktok_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
   * Nếu database cũ chưa có nhiệm vụ thì tạo nhiệm vụ mặc định.
   */

  await pool.query(`
    INSERT INTO tasks
    (title, description, task_url, points, is_main, active)
    SELECT
      'Nhiệm vụ TikTok',
      'Thực hiện nhiệm vụ theo hướng dẫn.',
      '',
      10,
      FALSE,
      TRUE
    WHERE NOT EXISTS (
      SELECT 1 FROM tasks
    );
  `);

  /*
   * Các gói đổi điểm.
   */

  await pool.query(`
    INSERT INTO packages
    (name, points, description)
    VALUES
      (
        'Đề xuất cơ bản',
        30,
        'Gói quảng bá cơ bản'
      ),
      (
        'Đề xuất nhiều tương tác',
        50,
        'Gói quảng bá tăng cường'
      ),
      (
        'Đề xuất cao',
        70,
        'Gói quảng bá cao'
      )
    ON CONFLICT (name)
    DO UPDATE SET
      points = EXCLUDED.points,
      description = EXCLUDED.description;
  `);

  /*
   * Tạo tài khoản admin từ Environment Variables.
   */

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [ADMIN_EMAIL]
    );

    if (existing.rowCount) {
      await pool.query(
        `
        UPDATE users
        SET
          password_hash = $1,
          is_admin = TRUE,
          is_blocked = FALSE
        WHERE email = $2
        `,
        [hash, ADMIN_EMAIL]
      );

      console.log("Admin account updated.");
    } else {
      await pool.query(
        `
        INSERT INTO users
        (
          email,
          password_hash,
          referral_code,
          is_admin
        )
        VALUES
        ($1, $2, $3, TRUE)
        `,
        [
          ADMIN_EMAIL,
          hash,
          createReferralCode()
        ]
      );

      console.log("Admin account created.");
    }
  }

  console.log("Database initialized successfully.");
}

/*
 * Health check
 */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "nhiemvutiktokfree"
    });
  } catch (error) {
    res.status(500).json({
      ok: false
    });
  }
});

/*
 * Trang chủ
 */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(publicDir, "index.html")
  );
});

/*
 * Đăng ký
 */

app.post("/api/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const referralCode = String(
      req.body.referral_code || ""
    ).trim().toUpperCase();

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Email không hợp lệ."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Mật khẩu phải có ít nhất 6 ký tự."
      });
    }

    const user = await transaction(async (client) => {
      const exists = await client.query(
        `
        SELECT id
        FROM users
        WHERE email = $1
        `,
        [email]
      );

      if (exists.rowCount) {
        throw new Error("Email đã được đăng ký.");
      }

      let referredBy = null;

      if (referralCode) {
        const referrer = await client.query(
          `
          SELECT id
          FROM users
          WHERE referral_code = $1
          `,
          [referralCode]
        );

        if (referrer.rowCount) {
          referredBy = referrer.rows[0].id;
        }
      }

      let referral = createReferralCode();

      while (
        (
          await client.query(
            `
            SELECT 1
            FROM users
            WHERE referral_code = $1
            `,
            [referral]
          )
        ).rowCount
      ) {
        referral = createReferralCode();
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const inserted = await client.query(
        `
        INSERT INTO users
        (
          email,
          password_hash,
          referral_code,
          referred_by
        )
        VALUES
        ($1, $2, $3, $4)
        RETURNING
          id,
          email,
          points,
          referral_code,
          is_admin,
          is_blocked
        `,
        [
          email,
          passwordHash,
          referral,
          referredBy
        ]
      );

      const newUser = inserted.rows[0];

      /*
       * Người giới thiệu nhận 20 điểm.
       */

      if (referredBy) {
        await addPoints(
          client,
          referredBy,
          20,
          `Giới thiệu người dùng ${email}`
        );
      }

      return newUser;
    });

    const token = await createSession(user);

    res.json({
      success: true,
      token,
      user: publicUser(user)
    });

  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: error.message || "Không thể đăng ký."
    });
  }
});

/*
 * Đăng nhập
 */

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const result = await pool.query(
      `
      SELECT
        id,
        email,
        password_hash,
        points,
        referral_code,
        is_admin,
        is_blocked
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

    if (user.is_blocked) {
      return res.status(403).json({
        error: "Tài khoản đã bị khóa."
      });
    }

    const passwordOk = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordOk) {
      return res.status(401).json({
        error: "Email hoặc mật khẩu không đúng."
      });
    }

    const token = await createSession(user);

    res.json({
      success: true,
      token,
      user: publicUser(user)
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Lỗi đăng nhập."
    });
  }
});

/*
 * Đăng xuất
 */

app.post("/api/logout", auth, (req, res) => {
  sessions.delete(req.token);

  res.json({
    success: true
  });
});

/*
 * Dashboard
 */

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const userResult = await pool.query(
      `
      SELECT
        id,
        email,
        points,
        referral_code,
        is_admin,
        is_blocked
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (!userResult.rowCount) {
      return res.status(404).json({
        error: "Không tìm thấy tài khoản."
      });
    }

    const doneResult = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM task_completions
      WHERE user_id = $1
      `,
      [req.user.id]
    );

    const refsResult = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM users
      WHERE referred_by = $1
      `,
      [req.user.id]
    );

    const checkinResult = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM checkins
      WHERE user_id = $1
        AND checkin_date = CURRENT_DATE
      `,
      [req.user.id]
    );

    res.json({
      user: publicUser(userResult.rows[0]),
      done: doneResult.rows[0].count,
      refs: refsResult.rows[0].count,
      checked_in_today:
        checkinResult.rows[0].count > 0
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không tải được dashboard."
    });
  }
});

/*
 * Danh sách nhiệm vụ
 */

app.get("/api/tasks", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        t.id,
        t.title,
        t.description,
        t.task_url,
        t.points,
        t.is_main,
        EXISTS (
          SELECT 1
          FROM task_completions c
          WHERE c.user_id = $1
            AND c.task_id = t.id
        ) AS completed
      FROM tasks t
      WHERE t.active = TRUE
      ORDER BY
        t.is_main DESC,
        t.id ASC
      `,
      [req.user.id]
    );

    res.json({
      tasks: result.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không tải được nhiệm vụ."
    });
  }
});

/*
 * Hoàn thành nhiệm vụ
 */

app.post("/api/tasks/:id/complete", auth, async (req, res) => {
  try {
    const taskId = Number(req.params.id);

    if (!Number.isInteger(taskId)) {
      return res.status(400).json({
        error: "Nhiệm vụ không hợp lệ."
      });
    }

    const pointsAdded = await transaction(
      async (client) => {

        const taskResult = await client.query(
          `
          SELECT *
          FROM tasks
          WHERE id = $1
            AND active = TRUE
          FOR UPDATE
          `,
          [taskId]
        );

        if (!taskResult.rowCount) {
          throw new Error(
            "Nhiệm vụ không tồn tại."
          );
        }

        const task = taskResult.rows[0];

        const completed = await client.query(
          `
          SELECT id
          FROM task_completions
          WHERE user_id = $1
            AND task_id = $2
          `,
          [
            req.user.id,
            taskId
          ]
        );

        if (completed.rowCount) {
          throw new Error(
            "Bạn đã hoàn thành nhiệm vụ này."
          );
        }

        await client.query(
          `
          INSERT INTO task_completions
          (user_id, task_id)
          VALUES
          ($1, $2)
          `,
          [
            req.user.id,
            taskId
          ]
        );

        await addPoints(
          client,
          req.user.id,
          task.points,
          `Hoàn thành: ${task.title}`
        );

        return task.points;
      }
    );

    res.json({
      success: true,
      points_added: pointsAdded
    });

  } catch (error) {
    console.error(error);

    res.status(400).json({
      error:
        error.message ||
        "Không thể hoàn thành nhiệm vụ."
    });
  }
});

/*
 * Điểm danh
 */

app.post("/api/checkin", auth, async (req, res) => {
  try {
    await transaction(async (client) => {

      const result = await client.query(
        `
        INSERT INTO checkins
        (user_id, checkin_date)
        VALUES
        ($1, CURRENT_DATE)
        ON CONFLICT
        (user_id, checkin_date)
        DO NOTHING
        RETURNING id
        `,
        [req.user.id]
      );

      if (!result.rowCount) {
        throw new Error(
          "Hôm nay bạn đã điểm danh rồi."
        );
      }

      await addPoints(
        client,
        req.user.id,
        10,
        "Điểm danh hằng ngày"
      );
    });

    res.json({
      success: true,
      points_added: 10
    });

  } catch (error) {
    res.status(400).json({
      error:
        error.message ||
        "Không thể điểm danh."
    });
  }
});

/*
 * Gói đổi điểm
 */

app.get("/api/packages", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        points,
        description
      FROM packages
      WHERE active = TRUE
      ORDER BY points ASC
      `
    );

    res.json({
      packages: result.rows
    });

  } catch (error) {
    res.status(500).json({
      error: "Không tải được gói."
    });
  }
});

/*
 * Tạo yêu cầu quảng bá
 */

app.post("/api/promotions", auth, async (req, res) => {
  try {
    const packageId = Number(
      req.body.package_id
    );

    const tiktokUrl = String(
      req.body.tiktok_url || ""
    ).trim();

    if (!validTikTokUrl(tiktokUrl)) {
      return res.status(400).json({
        error:
          "Link TikTok không hợp lệ."
      });
    }

    const promotion = await transaction(
      async (client) => {

        const packageResult = await client.query(
          `
          SELECT *
          FROM packages
          WHERE id = $1
            AND active = TRUE
          `,
          [packageId]
        );

        if (!packageResult.rowCount) {
          throw new Error(
            "Gói không tồn tại."
          );
        }

        const pkg = packageResult.rows[0];

        await removePoints(
          client,
          req.user.id,
          pkg.points,
          `Đổi điểm: ${pkg.name}`
        );

        const result = await client.query(
          `
          INSERT INTO promotions
          (
            user_id,
            package_name,
            points,
            tiktok_url
          )
          VALUES
          ($1, $2, $3, $4)
          RETURNING *
          `,
          [
            req.user.id,
            pkg.name,
            pkg.points,
            tiktokUrl
          ]
        );

        return result.rows[0];
      }
    );

    res.json({
      success: true,
      promotion
    });

  } catch (error) {
    res.status(400).json({
      error:
        error.message ||
        "Không thể tạo yêu cầu."
    });
  }
});

/*
 * Referral
 */

app.get("/api/referral", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT referral_code
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    const baseUrl =
      `${req.protocol}://${req.get("host")}`;

    const code =
      result.rows[0].referral_code;

    res.json({
      referral_code: code,
      referral_link:
        `${baseUrl}/?ref=${code}`
    });

  } catch {
    res.status(500).json({
      error: "Không tải được mã giới thiệu."
    });
  }
});

/*
 * Lịch sử điểm
 */

app.get("/api/history", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        amount,
        reason,
        created_at
      FROM point_transactions
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      history: result.rows
    });

  } catch {
    res.status(500).json({
      error: "Không tải được lịch sử."
    });
  }
});

/*
 * Bảng xếp hạng
 */

app.get("/api/leaderboard", auth, async (req, res) => {
  try {
    const daily = await pool.query(`
      SELECT
        u.id,
        u.email,
        COALESCE(
          SUM(
            CASE
              WHEN pt.amount > 0
              THEN pt.amount
              ELSE 0
            END
          ),
          0
        )::int AS score
      FROM users u
      LEFT JOIN point_transactions pt
        ON pt.user_id = u.id
        AND pt.created_at >= CURRENT_DATE
        AND pt.created_at <
            CURRENT_DATE + INTERVAL '1 day'
      WHERE
        u.is_admin = FALSE
        AND u.is_blocked = FALSE
      GROUP BY u.id
      ORDER BY score DESC, u.id ASC
      LIMIT 10
    `);

    const weekly = await pool.query(`
      SELECT
        u.id,
        u.email,
        COALESCE(
          SUM(
            CASE
              WHEN pt.amount > 0
              THEN pt.amount
              ELSE 0
            END
          ),
          0
        )::int AS score
      FROM users u
      LEFT JOIN point_transactions pt
        ON pt.user_id = u.id
        AND pt.created_at >= date_trunc(
          'week',
          CURRENT_DATE
        )
        AND pt.created_at <
          date_trunc(
            'week',
            CURRENT_DATE
          ) + INTERVAL '7 days'
      WHERE
        u.is_admin = FALSE
        AND u.is_blocked = FALSE
      GROUP BY u.id
      ORDER BY score DESC, u.id ASC
      LIMIT 10
    `);

    res.json({
      daily: daily.rows,
      weekly: weekly.rows,
      rewards: {
        daily: [50, 30, 20],
        weekly: [150, 100, 50]
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Không tải được bảng xếp hạng."
    });
  }
});

/*
 * ADMIN - thống kê
 */

app.get(
  "/api/admin/stats",
  auth,
  adminOnly,
  async (req, res) => {

    const users = await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM users
    `);

    const credits = await pool.query(`
      SELECT
        COALESCE(
          SUM(
            CASE
              WHEN amount > 0
              THEN amount
              ELSE 0
            END
          ),
          0
        )::int AS total
      FROM point_transactions
    `);

    const promotions = await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM promotions
    `);

    res.json({
      users: users.rows[0].count,
      credits: credits.rows[0].total,
      promotions: promotions.rows[0].count
    });
  }
);

/*
 * ADMIN - người dùng
 */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  async (req, res) => {

    const result = await pool.query(`
      SELECT
        id,
        email,
        points,
        referral_code,
        is_admin,
        is_blocked,
        created_at
      FROM users
      ORDER BY id DESC
      LIMIT 200
    `);

    res.json({
      users: result.rows
    });
  }
);

/*
 * ADMIN - khóa / mở khóa
 */

app.post(
  "/api/admin/users/:id/block",
  auth,
  adminOnly,
  async (req, res) => {

    const id = Number(req.params.id);
    const blocked = Boolean(req.body.blocked);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: "ID không hợp lệ."
      });
    }

    await pool.query(
      `
      UPDATE users
      SET is_blocked = $1
      WHERE id = $2
        AND is_admin = FALSE
      `,
      [
        blocked,
        id
      ]
    );

    res.json({
      success: true
    });
  }
);

/*
 * ADMIN - tạo nhiệm vụ
 */

app.post(
  "/api/admin/tasks",
  auth,
  adminOnly,
  async (req, res) => {

    try {
      const title = String(
        req.body.title || ""
      ).trim();

      const description = String(
        req.body.description || ""
      ).trim();

      const taskUrl = String(
        req.body.task_url || ""
      ).trim();

      const points = Number(
        req.body.points || 10
      );

      const isMain =
        Boolean(req.body.is_main);

      if (!title) {
        return res.status(400).json({
          error: "Tên nhiệm vụ không được trống."
        });
      }

      if (
        !Number.isInteger(points) ||
        points < 1 ||
        points > 1000
      ) {
        return res.status(400).json({
          error: "Điểm nhiệm vụ không hợp lệ."
        });
      }

      if (
        taskUrl &&
        !validTikTokUrl(taskUrl)
      ) {
        return res.status(400).json({
          error: "Link TikTok không hợp lệ."
        });
      }

      const result = await pool.query(
        `
        INSERT INTO tasks
        (
          title,
          description,
          task_url,
          points,
          is_main,
          active
        )
        VALUES
        ($1, $2, $3, $4, $5, TRUE)
        RETURNING *
        `,
        [
          title,
          description,
          taskUrl,
          points,
          isMain
        ]
      );

      res.json({
        success: true,
        task: result.rows[0]
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Không thể tạo nhiệm vụ."
      });
    }
  }
);

/*
 * ADMIN - danh sách quảng bá
 */

app.get(
  "/api/admin/promotions",
  auth,
  adminOnly,
  async (req, res) => {

    const result = await pool.query(`
      SELECT
        p.id,
        p.package_name,
        p.points,
        p.tiktok_url,
        p.status,
        p.created_at,
        u.email
      FROM promotions p
      JOIN users u
        ON u.id = p.user_id
      ORDER BY p.created_at DESC
      LIMIT 200
    `);

    res.json({
      promotions: result.rows
    });
  }
);

/*
 * ADMIN - đổi trạng thái quảng bá
 */

app.post(
  "/api/admin/promotions/:id/status",
  auth,
  adminOnly,
  async (req, res) => {

    const id = Number(req.params.id);
    const status = String(
      req.body.status || ""
    ).trim();

    const allowed = [
      "pending",
      "processing",
      "completed",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "Trạng thái không hợp lệ."
      });
    }

    const result = await pool.query(
      `
      UPDATE promotions
      SET status = $1
      WHERE id = $2
      RETURNING id
      `,
      [
        status,
        id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Không tìm thấy yêu cầu."
      });
    }

    res.json({
      success: true
    });
  }
);

/*
 * Lỗi chung
 */

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Lỗi máy chủ."
  });
});

/*
 * Khởi động server SAU KHI database sẵn sàng.
 */

initDatabase()
  .then(() => {

    app.listen(PORT, () => {
      console.log(
        `nhiemvutiktokfree running on port ${PORT}`
      );
    });

  })
  .catch((error) => {

    console.error(
      "STARTUP ERROR:",
      error
    );

    process.exit(1);
  });

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
