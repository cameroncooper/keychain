# Qt Quick framework assessment for Keychain

Date: 2026-11-12

Keychain can use Qt Quick and QML with a Rust application layer. C++ is not
required to reproduce Folio's appearance. The same QML controls and layout can
sit above either language. The recommended first candidate is CXX-Qt, compared
with Qt's official Rust Bridge in a small native Asahi prototype before selecting
a production bridge. A thin C++/QML frontend remains a practical fallback.

The [design assessment](GUI-DESIGN-FOLIO.md) covers the proposed appearance and
interaction model. The installed GUI and authentication agent remain the baseline during prototyping.

## Framework comparison

| Approach | Strength for Keychain | Cost or limitation | Assessment |
| --- | --- | --- | --- |
| QML with CXX-Qt and Rust | Existing Rust services and a typed Qt-facing model; flexible QObject/model integration | More explicit Qt concepts and generated C++ build machinery; application-specific unsafe interfaces may be needed | First candidate to validate |
| QML with official Qt Bridge for Rust | Rust-oriented objects, properties, signals and collection models with little manual glue | Technology Preview API and platform limitations | Strong candidate for a contained comparison |
| QML with a thin C++ frontend | Direct access to Qt APIs and Folio's implementation patterns | Another handwritten language plus IPC or an FFI boundary to the Rust application | Fallback if bridge integration becomes expensive |
| QML with qmetaobject-rs | Existing Rust/QML approach with QObject and model support | Different macro/inline-C++ machinery and compatibility evaluation | No clear advantage over the two primary candidates |
| Continue GPUI-kit | Existing working services and UI | Folio's QML components would need separate reimplementation | Useful during migration; does not meet the requested Qt Quick direction |

[qmetaobject-rs documents its macro and inline-C++ approach](https://github.com/woboq/qmetaobject-rs#readme).

Every Qt option uses Qt's C++ runtime, QML engine and platform plugins. Writing
application code in Rust does not make that stack entirely Rust or eliminate the
C++ compiler from the build. The language choice affects the frontend adapter,
not which Qt Quick rendering or styling capabilities are available.

## CXX-Qt

KDAB's CXX-Qt generates QObject representations and bridges Rust with Qt using
CXX. Version 0.10.0 was released on August 24, 2026. Its documented Cargo build
can generate/compile the Qt-facing code, package QML resources and link the Rust
executable; a standalone CMake project is not required.
[CXX-Qt introduction](https://kdab.github.io/cxx-qt/book/),
[0.10.0 release](https://github.com/KDAB/cxx-qt/releases/tag/v0.10.0),
[Cargo integration](https://kdab.github.io/cxx-qt/book/getting-started/4-cargo-executable.html)

For Keychain, QObject properties expose selected-item metadata, busy/error state
and actions; a list model feeds QML ListView. Rust workers perform inventory and
broker operations, then queue results onto the Qt object's owning thread. The
upstream threading example demonstrates this pattern.
[Threading example](https://github.com/KDAB/cxx-qt/blob/main/examples/qml_features/rust/src/threading.rs)

There is more explicit Qt lifetime/model machinery than in the official bridge.
For example, subclasses must pair model begin/end notifications correctly, and
the documented inherited functions include unsafe contracts. Keep that machinery
inside the frontend adapter; do not relax safety rules across the credential
core. [Model inheritance](https://kdab.github.io/cxx-qt/book/concepts/inheritance.html)

CXX-Qt documents regular desktop CI on x86_64, and says other architectures may
work without being regularly tested. Linux ARM64 must therefore be validated on
this machine. Its longer release history supports choosing it as the first
candidate, not a claim of proven Asahi compatibility.
[CXX-Qt platform coverage](https://kdab.github.io/cxx-qt/book/)

## Official Qt Bridge for Rust

The official bridge reached Technology Preview on October 27, 2026. It exposes
Rust structs, properties, slots, signals and collections to QML and supports
cross-thread invocation. Its ownership model uses Rc<RefCell<T>> for exposed
objects. Keep those objects on the GUI side; background Rust work should return
bounded results through the supported dispatch mechanism.
[Technology Preview announcement](https://www.qt.io/blog/qt-bridges-technology-preview-rust-csharp)

The bridge is intentionally focused on feeding a Qt Quick UI rather than wrapping
all Qt networking, multimedia or widget APIs. That fits Keychain: cryptography,
Apple protocols, storage and IPC already belong in Rust. It shares CXX-Qt types
and build foundations, and the projects are moving toward coexistence. They are
distinct APIs, not interchangeable crates.
[Qt Bridge and CXX-Qt foundations](https://www.qt.io/blog/qt-bridge-for-rust-0.3-cxx-qt-compatibility-and-soundness)

The current documentation lists Linux x86_64, Windows x64 and experimental macOS
ARM64 for Rust. It does not establish Linux ARM64 support. It also requires Qt
6.10 or later and warns that preview APIs/platform requirements can change. The
local machine has Qt 6.12.0 and Rust 1.98.1, so those installed versions are
promising; the actual dependency and architecture build remain prototype gates.
The marketing overview mentions broader ARM availability, but the specific Rust
platform matrix is the useful qualification for Asahi.
[Qt Bridges platform matrix and limitations](https://doc.qt.io/qtbridges/qtbridges-index.html),
[Qt Bridges overview](https://www.qt.io/development/qt-framework/qt-bridges)

For the official bridge, the first prototype must exercise model updates,
cancellation, object destruction while work is pending and the real Wayland
renderer. A demo window alone would not settle its suitability for a password
manager. Pin the selected release and isolate its API from the application model.

## C++ and the existing Rust backend

A C++ frontend does not require rewriting Keychain's broker or cryptography. It
could speak a deliberately bounded application protocol to Rust, or use a narrow
CXX adapter to a Rust library. Qt provides the QObject/view-model layer, while
Rust retains operations and authorization policy.

The existing broker protocol is not a complete desktop-management API: inventory
composition and some routes currently run in the Rust client. A separate C++
process would need an explicit client-service interface or a library adapter;
claiming it can simply attach to the broker would hide real integration work.
Avoid subprocess calls that send passwords through command-line arguments or
ordinary JSON output just to simplify the frontend.

Folio currently uses C++17, Qt Quick and CMake, with QML resources compiled into
the application. Its build includes filesystem/media-oriented dependencies that
Keychain does not need. Following Folio does not require copying that whole
backend or its dependency graph.
[Folio build](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/CMakeLists.txt)

## Suggested project boundary

```text
QML views and reusable controls
    |
Qt frontend adapter in Rust using the selected bridge
    |
Toolkit independent application model and request controller
    |
Existing Rust inventory, configuration and broker client
    |
Root broker and SEP driver
```

Separate the Qt frontend into its own workspace package and executable. Keep Qt
out of terminal/native-host/broker builds. During migration, choose one toolkit
per executable; GPUI and Qt do not need to share an event loop.

The current desktop data code is mostly reusable, but it imports GPUI icon types
and sits behind the existing desktop module. Extract plain item/category data,
inventory routing, selected-field operations and request-generation/cancellation
logic into toolkit-independent code. Map icons, colors and QObjects only in the
new frontend. QML should receive bounded view models, not the entire vault or
raw broker internals.

Keep password, notes and TOTP response owners in Rust until an intentional
presentation needs them. Do not put secrets in general list-model roles or
persistent properties. Clearing a QML property hides the value but cannot promise
all QString, JavaScript, renderer or GPU copies are erased. Rust, C++ and either
bridge share this display limitation.

All untrusted text is plain text; QML sources and assets are trusted packaged
resources, not downloaded plugins or credential-supplied code. The QML engine is
a JavaScript host, but it is not a browser DOM/WebView.
[Qt JavaScript host environment](https://doc.qt.io/qt-6/qtqml-javascript-hostenvironment.html),
[Qt resource deployment](https://doc.qt.io/qt-6/qtquick-deployment.html)

## Main GUI and authentication agent migration

Build the Qt main GUI first and leave the working authentication agent in place.
The app remains a broker client; it does not get direct SEP access. Preserve
selected-item bindings, operation generations, stale-response disposal, focus
handling and reveal lifetime limits.

Migrate the authentication agent separately after the main GUI proves the stack.
Retain the checked root-peer socket, private prompt protocol 4, separate process,
existing D-Bus activation name and TouchBar1 snapshot/cancel contract. A QML
visible property, window-open event or frame callback alone is not an equivalent
replacement for the existing rendered/visible/active acknowledgement sequence.
Verify the Qt/Wayland presentation behavior before permitting capture.

Reusable authorization depends on the kernel/broker session contract and client
integration. Do not cache decrypted credentials in QML to imitate Apple's
app-unlock experience.

## Prototype and selection gates

1. Use the same synthetic QML shell for the two Rust adapters: theme tokens,
   searchable metadata model, selection and a cancellable delayed fake reveal.
2. Build natively on Linux ARM64 with the installed Qt. Verify QML resource and
   plugin discovery, Wayland startup and clean shutdown.
3. Exercise model insertion/removal, rapid selection changes, late worker results,
   error/cancel paths and destruction while work is pending. Keep real secrets
   and SEP operations out of the prototype.
4. Check narrow layouts, scaling, keyboard focus, accessibility, RTL, theme changes
   and rendering with Qt Quick Test and actual Wayland visual inspection.
5. Compare bridge code size, unsafe contracts, workarounds and dependency pinning.
   Measure startup/RSS and scrolling with a representative synthetic inventory;
   do not infer performance from the backend language.
6. Select CXX-Qt unless the official bridge proves comparably reliable and
   materially simpler. If neither Rust adapter meets the platform/lifecycle
   requirements cleanly, use a thin C++ Qt adapter while retaining the Rust core.

Both CXX-Qt's Cargo build and conventional Qt CMake are viable. A Rust-led build
is the natural fit for the current workspace. Qt system libraries and QML/Wayland
plugins still need packaging; a single executable with embedded QML is not a
fully self-contained runtime. Include the selected bridge and Qt module licenses
in packaging review; Qt Bridges documents LGPLv3/commercial licensing.

This is a design and source assessment. Neither bridge has been built or
qualified on this Asahi host as part of this report, and no service binaries or
desktop settings were changed.

## Native prototype results

The [isolated prototype](../prototypes/qt/README.md) now builds the same QML view
and synthetic Rust model through CXX-Qt 0.10.0 and official Qt Bridge 0.4.1.
Both native aarch64 executables ran with Qt 6.12.0 on this Asahi host, including
real Wayland rendering and synthetic cancellation/lifecycle checks. This
establishes prototype feasibility beyond the published platform matrix, not
upstream ARM64 support or production qualification.

The UI and application model are shared. Each adapter has roughly sixty lines
of QObject/property/dispatch code; neither requires a handwritten C++ frontend.
The metadata list currently uses bounded full snapshots into QML. Native
incremental models and large-inventory benchmarks remain explicit selection
gates. Refer to the prototype README for commands, screenshots, dependency
pinning, validation scope and the observed portal-registration warning.

## Implementation decision

The user accepted the CXX-Qt prototype. The production frontend is now in the
separate [`desktop/`](../desktop/README.md) workspace, backed by the shared Rust
inventory and selected-field controller. The main GPUI app is removed; the GPUI
authentication agent and broker stay in place. Inventory rows are republished
only after inventory/search/filter changes, separately from selection and secret
presentation. An incremental Qt model and large-inventory benchmark remain
future work. Synthetic tests do not qualify new hardware behavior.
