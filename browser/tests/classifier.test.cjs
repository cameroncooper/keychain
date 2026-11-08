const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const fixtures = require("./fixtures/fields.json");
const context = vm.createContext({});
vm.runInContext(
  fs.readFileSync(`${__dirname}/../shared/forms/classifier.js`, "utf8"),
  context,
);
const classifier = context.KeychainFieldClassifier;
for (const fixture of fixtures) {
  test(`classification: ${fixture.name}`, () => {
    const fields = fixture.fields.map((field) => ({
      type: "text",
      eligible: true,
      maxLength: -1,
      ...field,
    }));
    const analysis = classifier.analyze(fields, fixture);
    assert.deepEqual(
      Array.from(analysis.roles, (role) => role.role),
      fixture.expected,
    );
    for (const role of analysis.roles) {
      assert.ok(role.reasons.length);
      assert.ok(
        ["explicit", "strong", "contextual", "none"].includes(role.confidence),
      );
    }
    if (fixture.usernameTarget !== undefined)
      assert.equal(
        classifier.uniqueBest(analysis.roles, "username"),
        fixture.usernameTarget,
      );
  });
}
test("equally supported username fields remain ambiguous", () => {
  const analysis = classifier.analyze([
    { type: "email", eligible: true },
    { type: "email", eligible: true },
  ]);
  assert.equal(classifier.uniqueBest(analysis.roles, "username"), null);
});
test("classification does not read editable values", () => {
  const field = {
    type: "password",
    eligible: true,
    get value() {
      throw new Error("value accessed");
    },
  };
  assert.equal(classifier.analyze([field]).roles[0].role, "password");
});
