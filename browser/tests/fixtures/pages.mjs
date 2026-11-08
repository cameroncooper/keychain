// The same declarative field corpus drives pure classifier tests and real DOM
// adapter tests in both packaged extensions. No external site or real secrets.
const escape = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
export function detectionPage(fixture) {
  const fields = fixture.fields
    .map((field) => {
      const attributes = {
        id: field.id,
        type: field.type ?? "text",
        name: field.name ?? "",
        autocomplete: field.autocomplete ?? "",
        placeholder: field.placeholder ?? "",
        "aria-label": field.ariaLabel ?? "",
        inputmode: field.inputMode ?? "",
      };
      if (field.labelledBy) attributes["aria-labelledby"] = field.id + "-label";
      if (field.maxLength !== undefined) attributes.maxlength = field.maxLength;
      const input =
        "<input " +
        Object.entries(attributes)
          .map(([key, value]) => key + '="' + escape(value) + '"')
          .join(" ") +
        (field.eligible === false ? " disabled" : "") +
        ">";
      return (
        (field.labelledBy
          ? '<span id="' +
            escape(field.id) +
            '-label">' +
            escape(field.labelledBy) +
            "</span>"
          : "") +
        (field.label
          ? "<label>" + escape(field.label) + input + "</label>"
          : input)
      );
    })
    .join("");
  const body =
    (fixture.heading ? "<h2>" + escape(fixture.heading) + "</h2>" : "") +
    fields +
    (fixture.buttons
      ? '<button type="submit">' + escape(fixture.buttons) + "</button>"
      : "");
  const open = fixture.formless
    ? '<div role="form">'
    : '<form action="/submit" method="post"' +
      (fixture.search ? ' role="search"' : "") +
      ">";
  const close = fixture.formless ? "</div>" : "</form>";
  const content = open + body + close;
  return (
    '<!doctype html><meta charset="utf-8"><title>Field detection fixture</title><style>body{font:14px system-ui;margin:24px}label,input{display:block}input{width:280px;height:32px;margin:6px 0 18px}</style><main id="fixture"></main><script>' +
    'window.submissions=0;document.addEventListener("submit",event=>{event.preventDefault();window.submissions++});' +
    (fixture.dynamic
      ? 'setTimeout(()=>{document.querySelector("#fixture").innerHTML=' +
        JSON.stringify(content) +
        "},30);"
      : 'document.querySelector("#fixture").innerHTML=' +
        JSON.stringify(content) +
        ";") +
    "</script>"
  );
}
