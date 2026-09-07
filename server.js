const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
  max: 10
});

app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function cleanEmail(v) {
  return String(v || '').trim().toLowerCase();
}

function cleanUsername(v) {
  return String(v || '').trim().replace(/\s+/g, '').slice(0, 30);
}

function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

function makeReferralCode() {
  return 'NV' + crypto.randomBytes(5).toString('hex').toUpperCase();
}

function isAdminUser(user) {
  return !!user && ADMIN_EMAIL && user.email === ADMIN_EMAIL;
}

function setAuthCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    `nv_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${
      process.env.NODE_ENV === 'production' ? '; Secure' : ''
    }`
  );
}

function clearAuthCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `nv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${
      process.env.NODE_ENV === 'production' ? '; Secure' : ''
    }`
  );
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};

  for (const part of raw.split(';')) {
    const i = part.indexOf('=');

    if (i > -1) {
      const key = part.slice(0, i).trim();
      const value = decodeURIComponent(part.slice(i + 1).trim());
      out[key] = value;
    }
  }

  return out;
}

function publicUser(u) {
  return {
    id: u.id,
    email: u.email,
    username: u.username,
    points: u.points,
    totalCompleted: u.total_completed,
    totalCheckins: u.total_checkins,
    streak: u.streak,
    lastCheckin: u.last_checkin,
    referralCode: u.referral_code,
    isAdmin: isAdminUser(u)
  };
}

async function getUserByToken(token) {
  if (!token) return null;

  const { rows } = await pool.query(`
    SELECT u.*
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = $1
      AND s.expires_at > NOW()
  `, [token]);

  return rows[0] || null;
}

async function auth(req, res, next) {
  try {
    const authorization = req.headers.authorization || '';

    const bearer =
      authorization.startsWith('Bearer ')
        ? authorization.slice(7).trim()
        : '';

    const cookies = parseCookies(req);
    const token = bearer || cookies.nv_session;

    const user = await getUserByToken(token);

    if (!user) {
      return res.status(401).json({
        error: 'Vui lòng đăng nhập.'
      });
    }

    req.user = user;
    req.sessionToken = token;

    next();
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Lỗi xác thực.'
    });
  }
}

function adminOnly(req, res, next) {
  if (!isAdminUser(req.user)) {
    return res.status(403).json({
      error: 'Bạn không có quyền admin.'
    });
  }

  next();
}

async function createSession(userId) {
  const token = makeToken();

  await pool.query(`
    INSERT INTO sessions(token, user_id, expires_at)
    VALUES($1, $2, NOW() + INTERVAL '30 days')
  `, [token, userId]);

  return token;
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      username TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 0,
      total_completed INTEGER NOT NULL DEFAULT 0,
      total_checkins INTEGER NOT NULL DEFAULT 0,
      streak INTEGER NOT NULL DEFAULT 0,
      last_checkin DATE,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      username TEXT NOT NULL,
      url TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 5,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS task_completions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      points INTEGER NOT NULL,
      completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, task_id)
    );

    CREATE TABLE IF NOT EXISTS daily_checkins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      checkin_date DATE NOT NULL,
      points INTEGER NOT NULL DEFAULT 10,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, checkin_date)
    );

    CREATE TABLE IF NOT EXISTS rewards (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      cost INTEGER NOT NULL CHECK(cost > 0),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS redemptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reward_id INTEGER NOT NULL REFERENCES rewards(id),
      reward_name TEXT NOT NULL,
      cost INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const taskCount = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM tasks
  `);

  if (taskCount.rows[0].count === 0) {
    const tasks = [
      [
        'Nhiệm vụ TikTok #1',
        '@uyn.uyn2229',
        'https://www.tiktok.com/@uyn.uyn2229',
        5
      ],
      [
        'Nhiệm vụ TikTok #2',
        '@maclaxinh1601',
        'https://www.tiktok.com/@maclaxinh1601',
        5
      ],
      [
        'Nhiệm vụ TikTok #3',
        '@thuychang612003',
        'https://www.tiktok.com/@thuychang612003',
        5
      ],
      [
        'Nhiệm vụ TikTok #4',
        '@jang.1.4.6',
        'https://www.tiktok.com/@jang.1.4.6',
        5
      ],
      [
        'Nhiệm vụ TikTok #5',
        '@ngocnhu_png',
        'https://www.tiktok.com/@ngocnhu_png',
        5
      ],
      [
        'Nhiệm vụ TikTok #6',
        '@thao.vo221',
        'https://www.tiktok.com/@thao.vo221',
        5
      ],
      [
        'Nhiệm vụ TikTok #7',
        '@vaycongsono1',
        'https://www.tiktok.com/@vaycongsono1',
        5
      ],
      [
        'Nhiệm vụ TikTok #8',
        '@.trang5689',
        'https://www.tiktok.com/@.trang5689',
        5
      ]
    ];

    for (const task of tasks) {
      await pool.query(`
        INSERT INTO tasks(title, username, url, points)
        VALUES($1, $2, $3, $4)
      `, task);
    }
  }

  const rewardCount = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM rewards
  `);

  if (rewardCount.rows[0].count === 0) {
    await pool.query(`
      INSERT INTO rewards(name, description, cost)
      VALUES
      ('Gói quà 50 điểm', 'Phần thưởng mẫu', 50),
      ('Gói quà 100 điểm', 'Phần thưởng mẫu', 100),
      ('Gói quà 250 điểm', 'Phần thưởng mẫu', 250)
    `);
  }
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

app.post('/api/register', async (req, res) => {
  const client = await pool.connect();

  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    const username =
      cleanUsername(req.body.username) ||
      email.split('@')[0];

    const referralCode =
      String(req.body.referralCode || '')
        .trim()
        .toUpperCase();

    if (!email || !email.includes('@')) {
      return res.status(400).json({
        error: 'Email không hợp lệ.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Mật khẩu cần ít nhất 6 ký tự.'
      });
    }

    await client.query('BEGIN');

    const exists = await client.query(
      'SELECT id FROM users WHERE email=$1',
      [email]
    );

    if (exists.rowCount) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Email đã được đăng ký.'
      });
    }

    let referrer = null;

    if (referralCode) {
      const r = await client.query(
        'SELECT id FROM users WHERE referral_code=$1 FOR UPDATE',
        [referralCode]
      );

      if (!r.rowCount) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'Mã giới thiệu không hợp lệ.'
        });
      }

      referrer = r.rows[0].id;
    }

    let code = makeReferralCode();

    while (
      (
        await client.query(
          'SELECT 1 FROM users WHERE referral_code=$1',
          [code]
        )
      ).rowCount
    ) {
      code = makeReferralCode();
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const inserted = await client.query(`
      INSERT INTO users(
        email,
        password_hash,
        username,
        referral_code,
        referred_by
      )
      VALUES($1,$2,$3,$4,$5)
      RETURNING *
    `, [
      email,
      passwordHash,
      username,
      code,
      referrer
    ]);

    const user = inserted.rows[0];

    /*
      Người giới thiệu +20 điểm
      Người đăng ký bằng mã +10 điểm
    */
    if (referrer) {
      await client.query(
        'UPDATE users SET points=points+20 WHERE id=$1',
        [referrer]
      );

      await client.query(
        'UPDATE users SET points=points+10 WHERE id=$1',
        [user.id]
      );
    }

    await client.query('COMMIT');

    const token = await createSession(user.id);

    setAuthCookie(res, token);

    res.json({
      message: 'Đăng ký thành công.',
      token,
      user: publicUser(user)
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(error);

    res.status(500).json({
      error: 'Không thể đăng ký.'
    });
  } finally {
    client.release();
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');

    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email=$1',
      [email]
    );

    if (
      !rows[0] ||
      !(await bcrypt.compare(
        password,
        rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: 'Email hoặc mật khẩu không đúng.'
      });
    }

    const token = await createSession(rows[0].id);

    setAuthCookie(res, token);

    res.json({
      message: 'Đăng nhập thành công.',
      token,
      user: publicUser(rows[0])
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Không thể đăng nhập.'
    });
  }
});

app.post('/api/logout', auth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM sessions WHERE token=$1',
      [req.sessionToken]
    );

    clearAuthCookie(res);

    res.json({
      ok: true
    });
  } catch {
    res.status(500).json({
      error: 'Lỗi đăng xuất.'
    });
  }
});

app.get('/api/me', auth, async (req, res) => {
  res.json({
    user: publicUser(req.user)
  });
});

app.get('/api/checkin/status', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT 1
    FROM daily_checkins
    WHERE user_id=$1
      AND checkin_date=CURRENT_DATE
  `, [req.user.id]);

  res.json({
    checkedIn: !!rows[0],
    points: 10
  });
});

app.post('/api/checkin', auth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const inserted = await client.query(`
      INSERT INTO daily_checkins(
        user_id,
        checkin_date,
        points
      )
      VALUES($1,CURRENT_DATE,10)
      ON CONFLICT(user_id,checkin_date)
      DO NOTHING
      RETURNING id
    `, [req.user.id]);

    if (!inserted.rowCount) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Hôm nay bạn đã điểm danh rồi.'
      });
    }

    const yesterday = await client.query(`
      SELECT 1
      FROM daily_checkins
      WHERE user_id=$1
        AND checkin_date=CURRENT_DATE-1
    `, [req.user.id]);

    const newStreak =
      yesterday.rowCount
        ? req.user.streak + 1
        : 1;

    await client.query(`
      UPDATE users
      SET
        points=points+10,
        total_checkins=total_checkins+1,
        streak=$1,
        last_checkin=CURRENT_DATE
      WHERE id=$2
    `, [
      newStreak,
      req.user.id
    ]);

    await client.query('COMMIT');

    res.json({
      message: 'Điểm danh thành công +10 điểm.',
      points: 10,
      streak: newStreak
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(error);

    res.status(500).json({
      error: 'Không thể điểm danh.'
    });
  } finally {
    client.release();
  }
});

app.get('/api/tasks/random', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT t.*
    FROM tasks t
    WHERE t.active=true
      AND NOT EXISTS (
        SELECT 1
        FROM task_completions c
        WHERE c.user_id=$1
          AND c.task_id=t.id
      )
    ORDER BY RANDOM()
    LIMIT 1
  `, [req.user.id]);

  if (!rows[0]) {
    return res.json({
      task: null
    });
  }

  res.json({
    task: rows[0]
  });
});

app.post('/api/tasks/:id/complete', auth, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return res.status(400).json({
      error: 'Nhiệm vụ không hợp lệ.'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const taskResult = await client.query(`
      SELECT *
      FROM tasks
      WHERE id=$1
        AND active=true
      FOR UPDATE
    `, [id]);

    if (!taskResult.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Nhiệm vụ không tồn tại.'
      });
    }

    const task = taskResult.rows[0];

    const inserted = await client.query(`
      INSERT INTO task_completions(
        user_id,
        task_id,
        points
      )
      VALUES($1,$2,$3)
      ON CONFLICT(user_id,task_id)
      DO NOTHING
      RETURNING id
    `, [
      req.user.id,
      id,
      task.points
    ]);

    if (!inserted.rowCount) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Bạn đã hoàn thành nhiệm vụ này.'
      });
    }

    await client.query(`
      UPDATE users
      SET
        points=points+$1,
        total_completed=total_completed+1
      WHERE id=$2
    `, [
      task.points,
      req.user.id
    ]);

    await client.query('COMMIT');

    res.json({
      message: `Hoàn thành nhiệm vụ +${task.points} điểm.`,
      points: task.points
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(error);

    res.status(500).json({
      error: 'Không thể hoàn thành nhiệm vụ.'
    });
  } finally {
    client.release();
  }
});

async function leaderboard(period) {
  const dateFilter =
    period === 'week'
      ? `c.completed_at >= date_trunc('week',CURRENT_DATE)`
      : `c.completed_at >= CURRENT_DATE`;

  const checkFilter =
    period === 'week'
      ? `d.checkin_date >= date_trunc('week',CURRENT_DATE)`
      : `d.checkin_date = CURRENT_DATE`;

  const { rows } = await pool.query(`
    SELECT
      u.id,
      u.username,

      COALESCE(
        (
          SELECT SUM(c.points)
          FROM task_completions c
          WHERE c.user_id=u.id
            AND ${dateFilter}
        ),
        0
      )::int

      +

      COALESCE(
        (
          SELECT SUM(d.points)
          FROM daily_checkins d
          WHERE d.user_id=u.id
            AND ${checkFilter}
        ),
        0
      )::int AS score

    FROM users u

    ORDER BY score DESC,u.id ASC

    LIMIT 20
  `);

  return rows;
}

app.get('/api/leaderboard/day', async (req, res) => {
  try {
    res.json({
      period: 'day',
      items: await leaderboard('day'),
      rewards: [50, 30, 20]
    });
  } catch {
    res.status(500).json({
      error: 'Lỗi bảng xếp hạng.'
    });
  }
});

app.get('/api/leaderboard/week', async (req, res) => {
  try {
    res.json({
      period: 'week',
      items: await leaderboard('week'),
      rewards: [150, 100, 50]
    });
  } catch {
    res.status(500).json({
      error: 'Lỗi bảng xếp hạng.'
    });
  }
});

/* =========================
   ĐỔI ĐIỂM
========================= */

app.get('/api/rewards', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      id,
      name,
      description,
      cost
    FROM rewards
    WHERE active=true
    ORDER BY cost ASC
  `);

  res.json({
    rewards: rows
  });
});

app.get('/api/redemptions', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      id,
      reward_name AS name,
      cost,
      status,
      created_at AS "createdAt"
    FROM redemptions
    WHERE user_id=$1
    ORDER BY id DESC
    LIMIT 30
  `, [req.user.id]);

  res.json({
    items: rows
  });
});

app.post('/api/rewards/:id/redeem', auth, async (req, res) => {
  const id = Number(req.params.id);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const rewardResult = await client.query(`
      SELECT *
      FROM rewards
      WHERE id=$1
        AND active=true
      FOR UPDATE
    `, [id]);

    if (!rewardResult.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Phần thưởng không tồn tại.'
      });
    }

    const reward = rewardResult.rows[0];

    const userResult = await client.query(`
      SELECT points
      FROM users
      WHERE id=$1
      FOR UPDATE
    `, [req.user.id]);

    const currentPoints = userResult.rows[0].points;

    if (currentPoints < reward.cost) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: `Bạn cần ${reward.cost} điểm để đổi.`
      });
    }

    await client.query(`
      UPDATE users
      SET points=points-$1
      WHERE id=$2
    `, [
      reward.cost,
      req.user.id
    ]);

    await client.query(`
      INSERT INTO redemptions(
        user_id,
        reward_id,
        reward_name,
        cost
      )
      VALUES($1,$2,$3,$4)
    `, [
      req.user.id,
      reward.id,
      reward.name,
      reward.cost
    ]);

    await client.query('COMMIT');

    res.json({
      message: 'Đổi điểm thành công. Yêu cầu đang chờ xử lý.',
      cost: reward.cost
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(error);

    res.status(500).json({
      error: 'Không thể đổi điểm.'
    });
  } finally {
    client.release();
  }
});

/* =========================
   GIỚI THIỆU BẠN BÈ
========================= */

app.get('/api/referral', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM users
    WHERE referred_by=$1
  `, [req.user.id]);

  res.json({
    code: req.user.referral_code,
    count: rows[0].count,
    referrerBonus: 20,
    newUserBonus: 10
  });
});

/* =========================
   ADMIN
========================= */

app.get('/api/admin/tasks', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT *
    FROM tasks
    ORDER BY id DESC
  `);

  res.json({
    tasks: rows
  });
});

app.post('/api/admin/tasks', auth, adminOnly, async (req, res) => {
  const title = String(req.body.title || '').trim();
  const username = String(req.body.username || '').trim();
  const url = String(req.body.url || '').trim();

  const points = Math.max(
    1,
    Math.min(
      1000,
      Number(req.body.points) || 5
    )
  );

  if (
    !title ||
    !username ||
    !/^https?:\/\//i.test(url)
  ) {
    return res.status(400).json({
      error: 'Thông tin nhiệm vụ không hợp lệ.'
    });
  }

  const { rows } = await pool.query(`
    INSERT INTO tasks(
      title,
      username,
      url,
      points
    )
    VALUES($1,$2,$3,$4)
    RETURNING *
  `, [
    title,
    username,
    url,
    points
  ]);

  res.json({
    task: rows[0]
  });
});

app.delete('/api/admin/tasks/:id', auth, adminOnly, async (req, res) => {
  await pool.query(
    'DELETE FROM tasks WHERE id=$1',
    [Number(req.params.id)]
  );

  res.json({
    ok: true
  });
});

app.get('/api/admin/redemptions', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      r.id,
      r.reward_name AS name,
      r.cost,
      r.status,
      r.created_at AS "createdAt",
      u.username,
      u.email
    FROM redemptions r
    JOIN users u ON u.id=r.user_id
    ORDER BY r.id DESC
    LIMIT 100
  `);

  res.json({
    items: rows
  });
});

app.patch('/api/admin/redemptions/:id', auth, adminOnly, async (req, res) => {
  const status = String(req.body.status || '').trim();

  if (
    ![
      'pending',
      'approved',
      'done',
      'rejected'
    ].includes(status)
  ) {
    return res.status(400).json({
      error: 'Trạng thái không hợp lệ.'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const result = await client.query(`
      SELECT *
      FROM redemptions
      WHERE id=$1
      FOR UPDATE
    `, [Number(req.params.id)]);

    if (!result.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Không tìm thấy yêu cầu.'
      });
    }

    const redemption = result.rows[0];

    /*
      Nếu admin từ chối:
      hoàn lại điểm cho người dùng.
    */
    if (
      status === 'rejected' &&
      redemption.status !== 'rejected'
    ) {
      await client.query(`
        UPDATE users
        SET points=points+$1
        WHERE id=$2
      `, [
        redemption.cost,
        redemption.user_id
      ]);
    }

    await client.query(`
      UPDATE redemptions
      SET status=$1
      WHERE id=$2
    `, [
      status,
      redemption.id
    ]);

    await client.query('COMMIT');

    res.json({
      ok: true
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    res.status(500).json({
      error: 'Không thể cập nhật.'
    });
  } finally {
    client.release();
  }
});

/*
  Frontend
*/
app.get('*', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );
});

async function start() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `nhiemvutiktokfree listening on ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      'Database initialization failed:',
      error
    );

    process.exit(1);
  }
}

start();
