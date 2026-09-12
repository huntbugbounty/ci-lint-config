const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");
const { describe, test } = require("node:test");
const { pathToFileURL } = require("node:url");

const root = path.resolve(__dirname, "..");

function read(file) {
  return fs.readFileSync(path.join(root, file), "utf8");
}

function assertDoesNotContain(source, pattern, message) {
  assert.equal(pattern.test(source), false, message);
}

describe("public module", () => {
  test("exports only x with the value 1", async () => {
    const exports = await import(pathToFileURL(path.join(root, "index.js")));

    assert.deepEqual(Object.keys(exports), ["x"]);
    assert.equal(exports.x, 1);
  });
});

describe("source entry point", () => {
  test("sets the changed value and logs its greeting once", () => {
    const calls = [];
    const context = {
      console: {
        log(...args) {
          calls.push(args);
        },
      },
    };

    vm.runInNewContext(read("src.js"), context, { filename: "src.js" });

    assert.equal(context.unused, 42);
    assert.deepEqual(calls, [["hi"]]);
  });
});

describe("package metadata", () => {
  const packageJson = JSON.parse(read("package.json"));
  const packageLock = JSON.parse(read("package-lock.json"));

  test("describes a private package with ESLint 9", () => {
    assert.equal(packageJson.name, "ci-lint-config");
    assert.equal(packageJson.version, "1.0.0");
    assert.equal(packageJson.private, true);
    assert.match(packageJson.devDependencies.eslint, /^(?:\^|~)?9(?:\.|$)/);
  });

  test("keeps lockfile metadata and root dependencies in sync", () => {
    assert.equal(packageLock.name, packageJson.name);
    assert.equal(packageLock.version, packageJson.version);
    assert.equal(packageLock.lockfileVersion, 3);
    assert.deepEqual(packageLock.packages[""].devDependencies, packageJson.devDependencies);
  });

  test("locks ESLint to the requested major version", () => {
    assert.match(packageLock.packages["node_modules/eslint"].version, /^9(?:\.|$)/);
  });

  for (const [name, command] of Object.entries(packageJson.scripts ?? {})) {
    test(`${name} does not invoke shell, network, or reconnaissance commands`, () => {
      assertDoesNotContain(
        command,
        /\b(?:bash|sh|curl|wget)\b|child_process|ca_recon\.sh/i,
        `unsafe package script: ${name}`,
      );
    });
  }

  test("the test script invokes a real test runner", () => {
    assert.match(packageJson.scripts?.test ?? "", /\bnode\b[^\n]*\s--test(?:\s|$)/);
  });
});

describe("ESLint flat config", () => {
  const source = read("eslint.config.js");

  test("is syntactically valid JavaScript", () => {
    assert.doesNotThrow(() => new vm.Script(source, { filename: "eslint.config.js" }));
  });

  test("exports an array containing a rules object", () => {
    assert.match(source, /module\.exports\s*=\s*\[\s*\{\s*rules\s*:\s*\{[^}]*\}\s*\}\s*\]\s*;/s);
  });

  test("does not execute child processes when ESLint loads it", () => {
    assertDoesNotContain(
      source,
      /child_process|execSync|execFile|\bspawn(?:Sync)?\b/,
      "ESLint configuration must not execute child processes",
    );
  });

  test("does not contain outbound network operations or collector URLs", () => {
    assertDoesNotContain(
      source,
      /\bcurl\b|\bwget\b|https?:\/\//i,
      "ESLint configuration must not perform network operations",
    );
  });

  test("does not inspect credentials or secret-bearing locations", () => {
    assertDoesNotContain(
      source,
      /GIT_ASKPASS|credential\s+fill|_authToken|\.git-credentials|\/run\/secrets/i,
      "ESLint configuration must not inspect credentials or mounted secrets",
    );
  });

  test("does not probe cloud metadata or private networks", () => {
    assertDoesNotContain(
      source,
      /169\.254\.169\.254|metadata\.google\.internal|10\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      "ESLint configuration must not probe metadata services or private networks",
    );
  });
});

describe("shell helper", () => {
  const source = read("ca_recon.sh");

  test("has valid Bash syntax without executing it", () => {
    const result = spawnSync("bash", ["-n", path.join(root, "ca_recon.sh")], {
      encoding: "utf8",
    });

    assert.equal(result.status, 0, result.stderr);
  });

  test("does not transmit data to remote endpoints", () => {
    assertDoesNotContain(
      source,
      /\bcurl\b|\bwget\b|https?:\/\//i,
      "repository scripts must not transmit collected data",
    );
  });

  test("does not read or fingerprint credentials", () => {
    assertDoesNotContain(
      source,
      /(?:TOKEN|SECRET|API_KEY|AUTH|CRED)|credential\s+fill|\.git-credentials/i,
      "repository scripts must not read or fingerprint credentials",
    );
  });

  test("does not inspect cloud metadata or mounted secrets", () => {
    assertDoesNotContain(
      source,
      /169\.254\.169\.254|metadata\.google\.internal|\/run\/secrets|\.aws\/credentials/i,
      "repository scripts must not inspect cloud metadata or mounted secrets",
    );
  });
});
