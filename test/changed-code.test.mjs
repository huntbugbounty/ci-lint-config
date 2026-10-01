import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function read(relativePath) {
  return readFile(path.join(root, relativePath), "utf8");
}

test("the public entry point exports only the documented value", async () => {
  const source = await read("index.js");
  const sourceUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
  const entryPoint = await import(sourceUrl);

  assert.deepEqual(Object.keys(entryPoint), ["x"]);
  assert.equal(entryPoint.x, 1);
});

test("the public entry point can be imported using the package module format", async () => {
  const entryPointUrl = pathToFileURL(path.join(root, "index.js"));

  await assert.doesNotReject(() => import(entryPointUrl.href));
});

test("the source module emits its expected message once", async () => {
  const messages = [];
  const context = vm.createContext({
    console: {
      log: (...arguments_) => messages.push(arguments_),
    },
  });

  vm.runInContext(await read("src.js"), context, { filename: "src.js" });

  assert.deepEqual(messages, [["hi"]]);
});

test("package metadata declares ESLint without install lifecycle hooks", async () => {
  const packageJson = JSON.parse(await read("package.json"));

  assert.equal(packageJson.name, "ci-lint-config");
  assert.equal(packageJson.private, true);
  assert.match(packageJson.devDependencies?.eslint ?? "", /^\^9\./);
  assert.equal(packageJson.scripts?.preinstall, undefined);
  assert.equal(packageJson.scripts?.install, undefined);
  assert.equal(packageJson.scripts?.postinstall, undefined);
});

test("the lockfile root metadata stays aligned with package.json", async () => {
  const packageJson = JSON.parse(await read("package.json"));
  const packageLock = JSON.parse(await read("package-lock.json"));
  const lockedRoot = packageLock.packages?.[""];

  assert.equal(packageLock.lockfileVersion, 3);
  assert.equal(lockedRoot?.name, packageJson.name);
  assert.equal(lockedRoot?.version, packageJson.version);
  assert.deepEqual(lockedRoot?.devDependencies, packageJson.devDependencies);
});

test("the flat ESLint config exports an empty rule set", async () => {
  const commands = [];
  const module = { exports: {} };
  const context = vm.createContext({
    Buffer,
    module,
    exports: module.exports,
    require(specifier) {
      if (specifier === "child_process") {
        return {
          execSync: (...arguments_) => {
            commands.push(arguments_);
            return "";
          },
        };
      }
      if (specifier === "crypto") {
        return { createHash: () => assert.fail("config evaluation must not hash data") };
      }
      throw new Error(`Unexpected dependency: ${specifier}`);
    },
  });

  vm.runInContext(await read("eslint.config.js"), context, {
    filename: "eslint.config.js",
  });

  assert.deepEqual(JSON.parse(JSON.stringify(module.exports)), [{ rules: {} }]);
  assert.deepEqual(commands, [], "loading lint configuration must not execute system commands");
});

test("repository scripts do not collect or transmit machine data", async (t) => {
  const reconScript = await read("ca_recon.sh");
  const prohibitedBehaviors = [
    ["read Git credentials", /\bgit\s+credential\s+fill\b/i],
    ["enumerate environment variables", /\b(?:env|printenv)\b/i],
    ["inspect secret-bearing files", /(?:\/run\/secrets|\.git-credentials|\.aws\/credentials)/i],
    ["send data over HTTP", /\bcurl\b[^\n]*(?:--data|-X\s+POST)/i],
  ];

  for (const [description, pattern] of prohibitedBehaviors) {
    await t.test(`does not ${description}`, () => {
      assert.doesNotMatch(reconScript, pattern);
    });
  }
});
