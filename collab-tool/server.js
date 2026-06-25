const http = require("http");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 3000);
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const db = {
  users: [],
  sessions: new Map(),
  projects: [],
  tasks: [],
  comments: [],
  notifications: [],
};

const sockets = new Map();

function uid(prefix) {
  return prefix + "_" + crypto.randomBytes(8).toString("hex");
}

function now() {
  return new Date().toISOString();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return salt + ":" + hash;
}

function verifyPassword(password, stored) {
  const [salt, original] = stored.split(":");
  const attempt = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(original, "hex"), attempt);
}

function parseCookies(header = "") {
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        return [decodeURIComponent(part.slice(0, index)), decodeURIComponent(part.slice(index + 1))];
      })
  );
}

function publicUser(user) {
  if (!user) return null;
  return { id: user.id, name: user.name, email: user.email, initials: initials(user.name) };
}

function initials(name) {
  return String(name || "?")
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0] || "")
    .join("")
    .toUpperCase();
}

function getUserFromReq(req) {
  const sid = parseCookies(req.headers.cookie || "").sid;
  const userId = sid && db.sessions.get(sid);
  return db.users.find((user) => user.id === userId) || null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Request body is too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
  });
}

function send(res, status, payload, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(JSON.stringify(payload));
}

function sendHtml(res) {
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(INDEX_HTML);
}

function requireAuth(req, res) {
  const user = getUserFromReq(req);
  if (!user) send(res, 401, { error: "Please sign in first." });
  return user;
}

function canAccessProject(userId, project) {
  return project && project.memberIds.includes(userId);
}

function taskPayload(task) {
  return {
    ...task,
    assignee: publicUser(db.users.find((user) => user.id === task.assigneeId)),
    creator: publicUser(db.users.find((user) => user.id === task.creatorId)),
    comments: db.comments
      .filter((comment) => comment.taskId === task.id)
      .map((comment) => ({
        ...comment,
        author: publicUser(db.users.find((user) => user.id === comment.authorId)),
      })),
  };
}

function projectPayload(project) {
  return {
    ...project,
    members: project.memberIds.map((id) => publicUser(db.users.find((user) => user.id === id))).filter(Boolean),
    tasks: db.tasks.filter((task) => task.projectId === project.id).map(taskPayload),
  };
}

function createNotification(userId, type, message, projectId, taskId) {
  const notification = {
    id: uid("note"),
    userId,
    type,
    message,
    projectId,
    taskId,
    read: false,
    createdAt: now(),
  };
  db.notifications.unshift(notification);
  emitToUser(userId, { type: "notification", notification });
  return notification;
}

function emitToProject(projectId, event) {
  const project = db.projects.find((item) => item.id === projectId);
  if (!project) return;
  for (const userId of project.memberIds) emitToUser(userId, event);
}

function emitToUser(userId, event) {
  const set = sockets.get(userId);
  if (!set) return;
  for (const socket of set) sendWs(socket, JSON.stringify(event));
}

function routeParts(pathname) {
  return pathname.split("/").filter(Boolean);
}

async function handleApi(req, res, pathname) {
  try {
    const method = req.method || "GET";
    const parts = routeParts(pathname);

    if (method === "POST" && pathname === "/api/register") {
      const body = await readBody(req);
      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!name || !email || password.length < 6) {
        return send(res, 400, { error: "Name, email, and a 6+ character password are required." });
      }
      if (db.users.some((user) => user.email === email)) {
        return send(res, 409, { error: "That email is already registered." });
      }
      const user = { id: uid("user"), name, email, passwordHash: hashPassword(password), createdAt: now() };
      db.users.push(user);
      const sid = uid("sid");
      db.sessions.set(sid, user.id);
      seedFirstProject(user);
      return send(res, 201, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(sid) });
    }

    if (method === "POST" && pathname === "/api/login") {
      const body = await readBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const user = db.users.find((item) => item.email === email);
      if (!user || !verifyPassword(password, user.passwordHash)) {
        return send(res, 401, { error: "Email or password is incorrect." });
      }
      const sid = uid("sid");
      db.sessions.set(sid, user.id);
      return send(res, 200, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(sid) });
    }

    if (method === "POST" && pathname === "/api/logout") {
      const sid = parseCookies(req.headers.cookie || "").sid;
      if (sid) db.sessions.delete(sid);
      return send(res, 200, { ok: true }, { "Set-Cookie": "sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" });
    }

    if (method === "GET" && pathname === "/api/me") {
      const user = requireAuth(req, res);
      if (!user) return;
      return send(res, 200, { user: publicUser(user) });
    }

    const user = requireAuth(req, res);
    if (!user) return;

    if (method === "GET" && pathname === "/api/users") {
      return send(res, 200, { users: db.users.map(publicUser) });
    }

    if (method === "GET" && pathname === "/api/projects") {
      const projects = db.projects.filter((project) => canAccessProject(user.id, project)).map(projectPayload);
      return send(res, 200, { projects });
    }

    if (method === "POST" && pathname === "/api/projects") {
      const body = await readBody(req);
      const name = String(body.name || "").trim();
      const description = String(body.description || "").trim();
      const memberIds = Array.isArray(body.memberIds) ? body.memberIds.filter((id) => db.users.some((user) => user.id === id)) : [];
      if (!name) return send(res, 400, { error: "Project name is required." });
      const project = {
        id: uid("project"),
        name,
        description,
        ownerId: user.id,
        memberIds: Array.from(new Set([user.id, ...memberIds])),
        createdAt: now(),
      };
      db.projects.push(project);
      for (const id of project.memberIds) {
        if (id !== user.id) createNotification(id, "project", user.name + " added you to " + project.name, project.id, null);
      }
      emitToProject(project.id, { type: "projects:changed", project: projectPayload(project) });
      return send(res, 201, { project: projectPayload(project) });
    }

    if (parts[0] === "api" && parts[1] === "projects" && parts[2]) {
      const project = db.projects.find((item) => item.id === parts[2]);
      if (!canAccessProject(user.id, project)) return send(res, 404, { error: "Project not found." });

      if (method === "GET" && parts.length === 3) {
        return send(res, 200, { project: projectPayload(project) });
      }

      if (method === "POST" && parts[3] === "tasks" && parts.length === 4) {
        const body = await readBody(req);
        const title = String(body.title || "").trim();
        if (!title) return send(res, 400, { error: "Task title is required." });
        const assigneeId = project.memberIds.includes(body.assigneeId) ? body.assigneeId : user.id;
        const task = {
          id: uid("task"),
          projectId: project.id,
          title,
          description: String(body.description || "").trim(),
          status: validStatus(body.status),
          assigneeId,
          creatorId: user.id,
          priority: validPriority(body.priority),
          dueDate: String(body.dueDate || "").trim(),
          createdAt: now(),
          updatedAt: now(),
        };
        db.tasks.push(task);
        if (assigneeId !== user.id) createNotification(assigneeId, "assignment", user.name + " assigned you: " + task.title, project.id, task.id);
        emitToProject(project.id, { type: "project:update", project: projectPayload(project), message: user.name + " created " + task.title });
        return send(res, 201, { task: taskPayload(task), project: projectPayload(project) });
      }

      if (parts[3] === "tasks" && parts[4]) {
        const task = db.tasks.find((item) => item.id === parts[4] && item.projectId === project.id);
        if (!task) return send(res, 404, { error: "Task not found." });

        if (method === "PATCH" && parts.length === 5) {
          const body = await readBody(req);
          const previousAssignee = task.assigneeId;
          if (body.title !== undefined) task.title = String(body.title || "").trim() || task.title;
          if (body.description !== undefined) task.description = String(body.description || "").trim();
          if (body.status !== undefined) task.status = validStatus(body.status);
          if (body.assigneeId !== undefined && project.memberIds.includes(body.assigneeId)) task.assigneeId = body.assigneeId;
          if (body.priority !== undefined) task.priority = validPriority(body.priority);
          if (body.dueDate !== undefined) task.dueDate = String(body.dueDate || "").trim();
          task.updatedAt = now();
          if (task.assigneeId !== previousAssignee && task.assigneeId !== user.id) {
            createNotification(task.assigneeId, "assignment", user.name + " assigned you: " + task.title, project.id, task.id);
          }
          emitToProject(project.id, { type: "project:update", project: projectPayload(project), message: user.name + " updated " + task.title });
          return send(res, 200, { task: taskPayload(task), project: projectPayload(project) });
        }

        if (method === "POST" && parts[5] === "comments" && parts.length === 6) {
          const body = await readBody(req);
          const message = String(body.message || "").trim();
          if (!message) return send(res, 400, { error: "Comment cannot be empty." });
          const comment = { id: uid("comment"), taskId: task.id, projectId: project.id, authorId: user.id, message, createdAt: now() };
          db.comments.push(comment);
          const notify = new Set([task.creatorId, task.assigneeId].filter((id) => id && id !== user.id));
          for (const id of notify) createNotification(id, "comment", user.name + " commented on " + task.title, project.id, task.id);
          emitToProject(project.id, { type: "project:update", project: projectPayload(project), message: user.name + " commented on " + task.title });
          return send(res, 201, { comment, task: taskPayload(task), project: projectPayload(project) });
        }
      }
    }

    if (method === "GET" && pathname === "/api/notifications") {
      return send(res, 200, { notifications: db.notifications.filter((note) => note.userId === user.id).slice(0, 50) });
    }

    if (method === "PATCH" && pathname === "/api/notifications/read") {
      for (const note of db.notifications) {
        if (note.userId === user.id) note.read = true;
      }
      emitToUser(user.id, { type: "notifications:read" });
      return send(res, 200, { ok: true });
    }

    send(res, 404, { error: "Route not found." });
  } catch (error) {
    send(res, 400, { error: error.message || "Something went wrong." });
  }
}

function validStatus(status) {
  return ["todo", "doing", "review", "done"].includes(status) ? status : "todo";
}

function validPriority(priority) {
  return ["low", "medium", "high", "urgent"].includes(priority) ? priority : "medium";
}

function sessionCookie(sid) {
  return "sid=" + encodeURIComponent(sid) + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800";
}

function seedFirstProject(user) {
  if (db.projects.some((project) => project.ownerId === user.id)) return;
  const project = {
    id: uid("project"),
    name: "Launch Board",
    description: "A starter project with task cards, owners, comments, and live updates.",
    ownerId: user.id,
    memberIds: [user.id],
    createdAt: now(),
  };
  db.projects.push(project);
  db.tasks.push(
    {
      id: uid("task"),
      projectId: project.id,
      title: "Invite the team",
      description: "Create accounts in another browser and add teammates to a group project.",
      status: "todo",
      assigneeId: user.id,
      creatorId: user.id,
      priority: "high",
      dueDate: "",
      createdAt: now(),
      updatedAt: now(),
    },
    {
      id: uid("task"),
      projectId: project.id,
      title: "Discuss launch checklist",
      description: "Open this task and add comments to test task communication.",
      status: "doing",
      assigneeId: user.id,
      creatorId: user.id,
      priority: "medium",
      dueDate: "",
      createdAt: now(),
      updatedAt: now(),
    }
  );
}

function handleWs(req, socket) {
  const user = getUserFromReq(req);
  if (!user || req.headers.upgrade?.toLowerCase() !== "websocket") {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }

  const key = req.headers["sec-websocket-key"];
  const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: " +
      accept +
      "\r\n\r\n"
  );

  if (!sockets.has(user.id)) sockets.set(user.id, new Set());
  sockets.get(user.id).add(socket);
  sendWs(socket, JSON.stringify({ type: "connected", user: publicUser(user) }));

  socket.on("data", (buffer) => {
    const message = readWs(buffer);
    if (!message) return;
    try {
      const event = JSON.parse(message);
      if (event.type === "ping") sendWs(socket, JSON.stringify({ type: "pong", at: now() }));
    } catch {}
  });
  socket.on("close", () => sockets.get(user.id)?.delete(socket));
  socket.on("error", () => sockets.get(user.id)?.delete(socket));
}

function sendWs(socket, message) {
  if (socket.destroyed) return;
  const payload = Buffer.from(message);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x81, payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  socket.write(Buffer.concat([header, payload]));
}

function readWs(buffer) {
  const opcode = buffer[0] & 0x0f;
  if (opcode === 0x8) return null;
  let length = buffer[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    length = Number(buffer.readBigUInt64BE(offset));
    offset += 8;
  }
  const masked = (buffer[1] & 0x80) === 0x80;
  let mask;
  if (masked) {
    mask = buffer.slice(offset, offset + 4);
    offset += 4;
  }
  const payload = buffer.slice(offset, offset + length);
  if (masked) {
    for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
  }
  return payload.toString("utf8");
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/api/")) return handleApi(req, res, url.pathname);
  if (url.pathname === "/" || url.pathname === "/app") return sendHtml(res);
  res.writeHead(302, { Location: "/" });
  res.end();
});

server.on("upgrade", (req, socket) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/ws") return handleWs(req, socket);
  socket.destroy();
});

server.listen(PORT, () => {
  console.log("Collaborative board running at http://localhost:" + PORT);
});

const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Collaborative Board</title>
  <style>
    :root {
      --ink: #1d2433;
      --muted: #697386;
      --line: #d8dee9;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --blue: #2563eb;
      --green: #16a34a;
      --red: #dc2626;
      --amber: #d97706;
      --violet: #7c3aed;
      --shadow: 0 16px 50px rgba(29, 36, 51, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: var(--bg);
      min-height: 100vh;
    }
    button, input, textarea, select { font: inherit; }
    button {
      border: 0;
      border-radius: 7px;
      background: var(--blue);
      color: #fff;
      font-weight: 700;
      padding: 10px 13px;
      cursor: pointer;
    }
    button.secondary { background: #eef2f7; color: var(--ink); }
    button.ghost { background: transparent; color: var(--muted); padding: 8px; }
    button.danger { background: var(--red); }
    button:disabled { opacity: .55; cursor: not-allowed; }
    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #fff;
      color: var(--ink);
      padding: 10px 11px;
      outline: none;
    }
    input:focus, textarea:focus, select:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37, 99, 235, .12); }
    textarea { min-height: 92px; resize: vertical; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 0; }
    .auth-shell {
      min-height: 100vh;
      display: grid;
      grid-template-columns: minmax(320px, 440px) 1fr;
      background:
        linear-gradient(135deg, rgba(37,99,235,.18), transparent 36%),
        linear-gradient(315deg, rgba(22,163,74,.13), transparent 42%),
        #f7f9fe;
    }
    .auth-panel {
      background: var(--panel);
      min-height: 100vh;
      padding: 46px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 24px;
      box-shadow: var(--shadow);
    }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 900; font-size: 22px; }
    .mark { width: 38px; height: 38px; border-radius: 8px; display: grid; place-items: center; background: var(--ink); color: #fff; }
    .auth-panel h1 { margin: 0; font-size: 36px; line-height: 1.05; letter-spacing: 0; }
    .auth-panel p { color: var(--muted); margin: 0; line-height: 1.55; }
    .auth-form { display: grid; gap: 14px; }
    .auth-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .auth-art { padding: 44px; display: grid; align-content: center; gap: 18px; }
    .preview-board {
      display: grid;
      grid-template-columns: repeat(3, minmax(180px, 1fr));
      gap: 16px;
      max-width: 900px;
    }
    .preview-col, .preview-card {
      background: rgba(255,255,255,.78);
      border: 1px solid rgba(216,222,233,.8);
      border-radius: 8px;
      padding: 14px;
      box-shadow: 0 8px 35px rgba(29,36,51,.08);
    }
    .preview-card { margin-top: 12px; min-height: 92px; }
    .line { height: 9px; border-radius: 4px; background: #dbe4f2; margin-bottom: 10px; }
    .line.short { width: 54%; }
    .line.green { background: rgba(22, 163, 74, .34); }
    .line.amber { background: rgba(217, 119, 6, .34); }
    .hidden { display: none !important; }
    .app {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 280px 1fr;
    }
    .sidebar {
      background: #111827;
      color: #f8fafc;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .top-brand { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
    .project-list { display: grid; gap: 8px; overflow: auto; }
    .project-item {
      width: 100%;
      text-align: left;
      background: transparent;
      color: #d1d5db;
      border: 1px solid transparent;
      display: grid;
      gap: 3px;
    }
    .project-item.active { background: #263244; border-color: #3b4a61; color: #fff; }
    .project-item span { color: #9ca3af; font-weight: 600; font-size: 12px; }
    .side-footer { margin-top: auto; display: grid; gap: 10px; }
    .main {
      display: grid;
      grid-template-rows: auto 1fr;
      min-width: 0;
    }
    .header {
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      padding: 15px 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .header h2 { margin: 0; font-size: 23px; }
    .header p { margin: 4px 0 0; color: var(--muted); }
    .header-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      border-radius: 999px;
      padding: 7px 10px;
      background: #eef2f7;
      color: #334155;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }
    .live-dot { width: 8px; height: 8px; border-radius: 99px; background: var(--green); }
    .board {
      min-width: 0;
      overflow: auto;
      padding: 18px;
      display: grid;
      grid-template-columns: repeat(4, minmax(240px, 1fr));
      gap: 14px;
      align-items: start;
    }
    .column {
      background: #eef2f7;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      min-height: calc(100vh - 136px);
      padding: 12px;
      display: grid;
      grid-template-rows: auto 1fr;
      gap: 10px;
    }
    .column-title { display: flex; justify-content: space-between; align-items: center; font-weight: 900; }
    .cards { display: grid; gap: 10px; align-content: start; min-height: 80px; }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      display: grid;
      gap: 10px;
      box-shadow: 0 8px 18px rgba(29,36,51,.06);
      cursor: pointer;
    }
    .card:hover { border-color: #b9c4d6; }
    .card h3 { margin: 0; font-size: 15px; line-height: 1.35; }
    .card p { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.4; }
    .card-meta { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .avatar {
      width: 30px;
      height: 30px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: #dbeafe;
      color: #1d4ed8;
      font-size: 12px;
      font-weight: 900;
    }
    .priority { border-radius: 999px; padding: 4px 8px; font-size: 11px; font-weight: 900; text-transform: uppercase; }
    .priority.low { background: #dcfce7; color: #166534; }
    .priority.medium { background: #e0f2fe; color: #075985; }
    .priority.high { background: #fef3c7; color: #92400e; }
    .priority.urgent { background: #fee2e2; color: #991b1b; }
    .modal {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, .42);
      display: grid;
      place-items: center;
      padding: 18px;
      z-index: 20;
    }
    .dialog {
      width: min(760px, 100%);
      max-height: min(860px, 94vh);
      overflow: auto;
      background: var(--panel);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 18px;
      display: grid;
      gap: 14px;
    }
    .dialog-head { display: flex; align-items: start; justify-content: space-between; gap: 14px; }
    .dialog h2 { margin: 0; font-size: 21px; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .form-actions { display: flex; justify-content: flex-end; gap: 10px; flex-wrap: wrap; }
    .task-detail { display: grid; grid-template-columns: minmax(0, 1fr) 280px; gap: 16px; }
    .comments { display: grid; gap: 10px; max-height: 300px; overflow: auto; padding-right: 4px; }
    .comment {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfdff;
    }
    .comment strong { display: block; font-size: 13px; }
    .comment span { color: var(--muted); font-size: 12px; }
    .comment p { margin: 7px 0 0; line-height: 1.45; }
    .toast-wrap {
      position: fixed;
      right: 16px;
      bottom: 16px;
      display: grid;
      gap: 10px;
      z-index: 30;
    }
    .toast {
      background: #111827;
      color: #fff;
      border-radius: 8px;
      padding: 11px 13px;
      box-shadow: var(--shadow);
      max-width: 360px;
    }
    .empty { color: var(--muted); border: 1px dashed #cbd5e1; border-radius: 8px; padding: 16px; text-align: center; }
    .error { color: var(--red); font-weight: 700; min-height: 20px; }
    @media (max-width: 900px) {
      .auth-shell { grid-template-columns: 1fr; }
      .auth-art { display: none; }
      .app { grid-template-columns: 1fr; }
      .sidebar { min-height: auto; }
      .board { grid-template-columns: repeat(4, minmax(235px, 78vw)); }
      .task-detail { grid-template-columns: 1fr; }
    }
    @media (max-width: 620px) {
      .auth-panel { padding: 28px; }
      .header { align-items: start; flex-direction: column; }
      .grid-2 { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div id="auth" class="auth-shell hidden">
    <section class="auth-panel">
      <div class="brand"><div class="mark">CB</div><span>Collab Board</span></div>
      <div>
        <h1>Projects, tasks, and team talk in one board.</h1>
        <p>Create group projects, assign task cards, and keep every discussion attached to the work.</p>
      </div>
      <form id="authForm" class="auth-form">
        <label id="nameWrap">Name<input id="name" autocomplete="name" placeholder="Ada Lovelace"></label>
        <label>Email<input id="email" type="email" autocomplete="email" placeholder="ada@example.com" required></label>
        <label>Password<input id="password" type="password" autocomplete="current-password" placeholder="6 characters minimum" required></label>
        <div class="error" id="authError"></div>
        <div class="auth-actions">
          <button id="authSubmit" type="submit">Create account</button>
          <button class="secondary" id="toggleAuth" type="button">Sign in instead</button>
        </div>
      </form>
    </section>
    <section class="auth-art">
      <div class="preview-board">
        <div class="preview-col"><b>To do</b><div class="preview-card"><div class="line"></div><div class="line short"></div></div><div class="preview-card"><div class="line amber"></div><div class="line short"></div></div></div>
        <div class="preview-col"><b>Doing</b><div class="preview-card"><div class="line green"></div><div class="line"></div><div class="line short"></div></div></div>
        <div class="preview-col"><b>Done</b><div class="preview-card"><div class="line"></div><div class="line green short"></div></div></div>
      </div>
    </section>
  </div>

  <div id="app" class="app hidden">
    <aside class="sidebar">
      <div class="top-brand">
        <div class="brand"><div class="mark">CB</div><span>Collab Board</span></div>
        <span class="pill"><span class="live-dot"></span><span id="liveState">Live</span></span>
      </div>
      <button id="newProjectBtn">+ Project</button>
      <div id="projectList" class="project-list"></div>
      <div class="side-footer">
        <div class="pill" id="userPill"></div>
        <button class="secondary" id="logoutBtn">Sign out</button>
      </div>
    </aside>
    <main class="main">
      <header class="header">
        <div>
          <h2 id="projectTitle">Project board</h2>
          <p id="projectDescription"></p>
        </div>
        <div class="header-actions">
          <button class="secondary" id="notificationsBtn">Notifications <span id="notificationCount">0</span></button>
          <button id="newTaskBtn">+ Task</button>
        </div>
      </header>
      <section id="board" class="board"></section>
    </main>
  </div>

  <div id="modalRoot"></div>
  <div id="toasts" class="toast-wrap"></div>

  <script>
    var state = {
      user: null,
      users: [],
      projects: [],
      currentProjectId: null,
      notifications: [],
      authMode: "register",
      socket: null
    };

    var columns = [
      { id: "todo", label: "To do" },
      { id: "doing", label: "Doing" },
      { id: "review", label: "Review" },
      { id: "done", label: "Done" }
    ];

    var $ = function (id) { return document.getElementById(id); };

    async function api(path, options) {
      var response = await fetch(path, Object.assign({
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin"
      }, options || {}));
      var data = await response.json().catch(function () { return {}; });
      if (!response.ok) throw new Error(data.error || "Request failed");
      return data;
    }

    function escapeHtml(value) {
      return String(value || "").replace(/[&<>"']/g, function (char) {
        return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char];
      });
    }

    function fmtDate(value) {
      if (!value) return "";
      return new Date(value).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    }

    function currentProject() {
      return state.projects.find(function (project) { return project.id === state.currentProjectId; }) || state.projects[0] || null;
    }

    async function boot() {
      bindEvents();
      try {
        var me = await api("/api/me");
        state.user = me.user;
        await loadData();
        showApp();
      } catch {
        showAuth();
      }
    }

    function bindEvents() {
      $("toggleAuth").addEventListener("click", function () {
        state.authMode = state.authMode === "register" ? "login" : "register";
        renderAuthMode();
      });
      $("authForm").addEventListener("submit", submitAuth);
      $("logoutBtn").addEventListener("click", logout);
      $("newProjectBtn").addEventListener("click", openProjectModal);
      $("newTaskBtn").addEventListener("click", function () { openTaskModal(); });
      $("notificationsBtn").addEventListener("click", openNotificationsModal);
      renderAuthMode();
    }

    function renderAuthMode() {
      var register = state.authMode === "register";
      $("nameWrap").classList.toggle("hidden", !register);
      $("authSubmit").textContent = register ? "Create account" : "Sign in";
      $("toggleAuth").textContent = register ? "Sign in instead" : "Create account instead";
      $("authError").textContent = "";
    }

    async function submitAuth(event) {
      event.preventDefault();
      $("authError").textContent = "";
      try {
        var path = state.authMode === "register" ? "/api/register" : "/api/login";
        var data = await api(path, {
          method: "POST",
          body: JSON.stringify({
            name: $("name").value,
            email: $("email").value,
            password: $("password").value
          })
        });
        state.user = data.user;
        await loadData();
        showApp();
      } catch (error) {
        $("authError").textContent = error.message;
      }
    }

    async function loadData() {
      var users = await api("/api/users");
      var projects = await api("/api/projects");
      var notes = await api("/api/notifications");
      state.users = users.users;
      state.projects = projects.projects;
      state.notifications = notes.notifications;
      if (!state.currentProjectId && state.projects[0]) state.currentProjectId = state.projects[0].id;
    }

    function showAuth() {
      $("auth").classList.remove("hidden");
      $("app").classList.add("hidden");
    }

    function showApp() {
      $("auth").classList.add("hidden");
      $("app").classList.remove("hidden");
      connectSocket();
      render();
    }

    function connectSocket() {
      if (state.socket) state.socket.close();
      var proto = location.protocol === "https:" ? "wss:" : "ws:";
      state.socket = new WebSocket(proto + "//" + location.host + "/ws");
      state.socket.onopen = function () { $("liveState").textContent = "Live"; };
      state.socket.onclose = function () {
        $("liveState").textContent = "Offline";
        setTimeout(connectSocket, 1800);
      };
      state.socket.onmessage = function (event) {
        var message = JSON.parse(event.data);
        if (message.type === "project:update" && message.project) {
          upsertProject(message.project);
          toast(message.message || "Board updated");
          render();
        }
        if (message.type === "projects:changed" && message.project) {
          upsertProject(message.project);
          render();
        }
        if (message.type === "notification") {
          state.notifications.unshift(message.notification);
          toast(message.notification.message);
          renderNotificationsCount();
        }
        if (message.type === "notifications:read") {
          state.notifications.forEach(function (note) { note.read = true; });
          renderNotificationsCount();
        }
      };
    }

    function upsertProject(project) {
      var index = state.projects.findIndex(function (item) { return item.id === project.id; });
      if (index >= 0) state.projects[index] = project;
      else state.projects.unshift(project);
      if (!state.currentProjectId) state.currentProjectId = project.id;
    }

    function render() {
      renderProjects();
      renderBoard();
      renderNotificationsCount();
      $("userPill").textContent = state.user.name + " · " + state.user.email;
    }

    function renderProjects() {
      $("projectList").innerHTML = state.projects.map(function (project) {
        var active = project.id === state.currentProjectId ? " active" : "";
        return '<button class="project-item' + active + '" data-project="' + project.id + '"><strong>' + escapeHtml(project.name) + '</strong><span>' + project.members.length + ' members · ' + project.tasks.length + ' tasks</span></button>';
      }).join("") || '<div class="empty">No projects yet.</div>';
      Array.from(document.querySelectorAll("[data-project]")).forEach(function (button) {
        button.addEventListener("click", function () {
          state.currentProjectId = button.getAttribute("data-project");
          render();
        });
      });
    }

    function renderBoard() {
      var project = currentProject();
      if (!project) {
        $("projectTitle").textContent = "Project board";
        $("projectDescription").textContent = "";
        $("board").innerHTML = '<div class="empty">Create a project to begin.</div>';
        return;
      }
      $("projectTitle").textContent = project.name;
      $("projectDescription").textContent = project.description || "Members: " + project.members.map(function (member) { return member.name; }).join(", ");
      $("board").innerHTML = columns.map(function (column) {
        var tasks = project.tasks.filter(function (task) { return task.status === column.id; });
        return '<div class="column" data-status="' + column.id + '"><div class="column-title"><span>' + column.label + '</span><span class="pill">' + tasks.length + '</span></div><div class="cards">' + (tasks.map(renderCard).join("") || '<div class="empty">No cards</div>') + '</div></div>';
      }).join("");
      Array.from(document.querySelectorAll("[data-task]")).forEach(function (card) {
        card.addEventListener("click", function () { openTaskDetail(card.getAttribute("data-task")); });
      });
    }

    function renderCard(task) {
      var comments = task.comments ? task.comments.length : 0;
      var description = task.description ? '<p>' + escapeHtml(task.description).slice(0, 120) + '</p>' : "";
      return '<article class="card" data-task="' + task.id + '"><h3>' + escapeHtml(task.title) + '</h3>' + description + '<div class="card-meta"><span class="priority ' + task.priority + '">' + task.priority + '</span><span class="pill">' + comments + ' comments</span><div class="avatar" title="' + escapeHtml(task.assignee ? task.assignee.name : "Unassigned") + '">' + escapeHtml(task.assignee ? task.assignee.initials : "?") + '</div></div></article>';
    }

    function renderNotificationsCount() {
      var unread = state.notifications.filter(function (note) { return !note.read; }).length;
      $("notificationCount").textContent = unread;
    }

    function memberOptions(selected) {
      var project = currentProject();
      var members = project ? project.members : state.users;
      return members.map(function (user) {
        return '<option value="' + user.id + '"' + (user.id === selected ? " selected" : "") + '>' + escapeHtml(user.name) + '</option>';
      }).join("");
    }

    function openProjectModal() {
      modal('<div class="dialog"><div class="dialog-head"><h2>New project</h2><button class="ghost" data-close>Close</button></div><form id="projectForm" class="auth-form"><label>Name<input id="projectName" required></label><label>Description<textarea id="projectDesc"></textarea></label><label>Members<select id="projectMembers" multiple size="5">' + state.users.filter(function (user) { return user.id !== state.user.id; }).map(function (user) { return '<option value="' + user.id + '">' + escapeHtml(user.name) + " · " + escapeHtml(user.email) + '</option>'; }).join("") + '</select></label><div class="form-actions"><button class="secondary" type="button" data-close>Cancel</button><button>Create project</button></div></form></div>');
      $("projectForm").addEventListener("submit", async function (event) {
        event.preventDefault();
        var selected = Array.from($("projectMembers").selectedOptions).map(function (option) { return option.value; });
        var data = await api("/api/projects", { method: "POST", body: JSON.stringify({ name: $("projectName").value, description: $("projectDesc").value, memberIds: selected }) });
        upsertProject(data.project);
        state.currentProjectId = data.project.id;
        closeModal();
        render();
      });
    }

    function openTaskModal(task) {
      var editing = Boolean(task);
      var project = currentProject();
      if (!project) return toast("Create a project first.");
      modal('<div class="dialog"><div class="dialog-head"><h2>' + (editing ? "Edit task" : "New task") + '</h2><button class="ghost" data-close>Close</button></div><form id="taskForm" class="auth-form"><label>Title<input id="taskTitle" value="' + escapeHtml(task ? task.title : "") + '" required></label><label>Description<textarea id="taskDesc">' + escapeHtml(task ? task.description : "") + '</textarea></label><div class="grid-2"><label>Status<select id="taskStatus">' + statusOptions(task ? task.status : "todo") + '</select></label><label>Assignee<select id="taskAssignee">' + memberOptions(task ? task.assigneeId : state.user.id) + '</select></label></div><div class="grid-2"><label>Priority<select id="taskPriority">' + priorityOptions(task ? task.priority : "medium") + '</select></label><label>Due date<input id="taskDue" type="date" value="' + escapeHtml(task ? task.dueDate : "") + '"></label></div><div class="form-actions"><button class="secondary" type="button" data-close>Cancel</button><button>' + (editing ? "Save task" : "Create task") + '</button></div></form></div>');
      $("taskForm").addEventListener("submit", async function (event) {
        event.preventDefault();
        var body = {
          title: $("taskTitle").value,
          description: $("taskDesc").value,
          status: $("taskStatus").value,
          assigneeId: $("taskAssignee").value,
          priority: $("taskPriority").value,
          dueDate: $("taskDue").value
        };
        var path = "/api/projects/" + project.id + "/tasks" + (editing ? "/" + task.id : "");
        var method = editing ? "PATCH" : "POST";
        var data = await api(path, { method: method, body: JSON.stringify(body) });
        upsertProject(data.project);
        closeModal();
        render();
      });
    }

    function openTaskDetail(taskId) {
      var project = currentProject();
      var task = project.tasks.find(function (item) { return item.id === taskId; });
      if (!task) return;
      modal('<div class="dialog"><div class="dialog-head"><div><h2>' + escapeHtml(task.title) + '</h2><p style="margin:4px 0 0;color:var(--muted)">' + escapeHtml(task.description || "No description") + '</p></div><button class="ghost" data-close>Close</button></div><div class="task-detail"><section><div class="comments">' + (task.comments.map(function (comment) { return '<div class="comment"><strong>' + escapeHtml(comment.author.name) + '</strong><span>' + fmtDate(comment.createdAt) + '</span><p>' + escapeHtml(comment.message) + '</p></div>'; }).join("") || '<div class="empty">No comments yet.</div>') + '</div><form id="commentForm" class="auth-form" style="margin-top:12px"><label>Comment<textarea id="commentText" required></textarea></label><button>Add comment</button></form></section><aside class="auth-form"><label>Status<select id="detailStatus">' + statusOptions(task.status) + '</select></label><label>Assignee<select id="detailAssignee">' + memberOptions(task.assigneeId) + '</select></label><label>Priority<select id="detailPriority">' + priorityOptions(task.priority) + '</select></label><button id="editTask" class="secondary" type="button">Edit task</button></aside></div></div>');
      $("commentForm").addEventListener("submit", async function (event) {
        event.preventDefault();
        var data = await api("/api/projects/" + project.id + "/tasks/" + task.id + "/comments", { method: "POST", body: JSON.stringify({ message: $("commentText").value }) });
        upsertProject(data.project);
        openTaskDetail(task.id);
        render();
      });
      ["detailStatus", "detailAssignee", "detailPriority"].forEach(function (id) {
        $(id).addEventListener("change", async function () {
          var data = await api("/api/projects/" + project.id + "/tasks/" + task.id, { method: "PATCH", body: JSON.stringify({ status: $("detailStatus").value, assigneeId: $("detailAssignee").value, priority: $("detailPriority").value }) });
          upsertProject(data.project);
          render();
        });
      });
      $("editTask").addEventListener("click", function () { openTaskModal(task); });
    }

    function statusOptions(selected) {
      return columns.map(function (column) {
        return '<option value="' + column.id + '"' + (selected === column.id ? " selected" : "") + '>' + column.label + '</option>';
      }).join("");
    }

    function priorityOptions(selected) {
      return ["low", "medium", "high", "urgent"].map(function (priority) {
        return '<option value="' + priority + '"' + (selected === priority ? " selected" : "") + '>' + priority + '</option>';
      }).join("");
    }

    function openNotificationsModal() {
      modal('<div class="dialog"><div class="dialog-head"><h2>Notifications</h2><button class="ghost" data-close>Close</button></div><div class="comments">' + (state.notifications.map(function (note) { return '<div class="comment"><strong>' + escapeHtml(note.message) + '</strong><span>' + fmtDate(note.createdAt) + (note.read ? " · read" : " · new") + '</span></div>'; }).join("") || '<div class="empty">No notifications.</div>') + '</div><div class="form-actions"><button class="secondary" type="button" data-close>Close</button><button id="markRead" type="button">Mark all read</button></div></div>');
      $("markRead").addEventListener("click", async function () {
        await api("/api/notifications/read", { method: "PATCH", body: "{}" });
        state.notifications.forEach(function (note) { note.read = true; });
        closeModal();
        renderNotificationsCount();
      });
    }

    function modal(html) {
      $("modalRoot").innerHTML = '<div class="modal">' + html + '</div>';
      Array.from(document.querySelectorAll("[data-close]")).forEach(function (button) {
        button.addEventListener("click", closeModal);
      });
    }

    function closeModal() {
      $("modalRoot").innerHTML = "";
    }

    function toast(message) {
      var el = document.createElement("div");
      el.className = "toast";
      el.textContent = message;
      $("toasts").appendChild(el);
      setTimeout(function () { el.remove(); }, 3500);
    }

    async function logout() {
      await api("/api/logout", { method: "POST", body: "{}" });
      if (state.socket) state.socket.close();
      state = { user: null, users: [], projects: [], currentProjectId: null, notifications: [], authMode: "login", socket: null };
      renderAuthMode();
      showAuth();
    }

    boot();
  </script>
</body>
</html>`;
