    property int testStep: 0
    property int testTries: 0
    property var testFirst: null
    function check(condition, label) {
        if (!condition) { console.error("GUI SMOKE FAIL: " + label); Qt.exit(1); }
    }
    Timer {
        interval: 250
        running: true
        repeat: true
        onTriggered: {
            if (++win.testTries > 100) { console.error("GUI SMOKE TIMEOUT step " + win.testStep); Qt.exit(1); return; }
            switch (win.testStep) {
            case 0:
                if (win.items.length !== 2) return;
                if (win.testMode === "narrow") win.width = 640;
                win.check(win.tokens.background === (win.testMode === "light" ? "#f4f3ef" : "#16161a"), "explicit palette");
                win.check(win.font.pixelSize === 13 && search.font.pixelSize === 14, "typography");
                win.check(!categoryPane.visible || categoryPane.width === 190, "sidebar");
                if (!win.settled) return;
                win.check(Theme.radius === 0 && Theme.red.a === 1 && Theme.light === (win.testMode === "light"), "derived theme");
                win.check(win.state.auth.mode === "per-operation", "authorization mode");
                win.check(win.state.counts.All === 2 && win.state.counts.Code === 1 && win.state.counts.Passkey === 0, "category counts");
                win.check(win.state.refreshedAt > 0, "refresh time");
                win.check(credentialPane.view.count === 2, "list model");
                win.testFirst = credentialPane.view.itemAtIndex(1);
                search.text = "other"; ++win.testStep; break;
            case 1:
                win.check(win.items.length === 1, "search real inventory");
                // The surviving row keeps its delegate: the model changed in place.
                win.check(credentialPane.view.count === 1 && credentialPane.view.itemAtIndex(0) === win.testFirst, "rows update in place");
                search.clear(); win.act("filter", "Code");
                win.check(win.items.length === 1, "code filter");
                win.act("focus", "true"); win.act("reveal", "password"); ++win.testStep; break;
            case 2:
                if (win.state.busy) return;
                win.check(backend.revealed === "synthetic-password", "password reveal");
                win.check(win.state.hidesIn > 25 && win.state.hidesIn <= 30 && win.state.pendingField === null, "reveal lifetime");
                win.check(!backend.snapshot.includes("synthetic-password") && !backend.rows.includes("synthetic-password"), "metadata isolation");
                win.act("select", "11111111-1111-4111-8111-111111111111");
                win.check(!backend.revealed.length, "selection hides");
                win.act("reveal", "notes"); win.act("cancel"); ++win.testStep; break;
            case 3:
                win.check(!backend.revealed.length, "cancel drops late result");
                win.act("reveal", "notes"); ++win.testStep; break;
            case 4:
                if (win.state.busy) return;
                win.check(backend.revealed === "synthetic-notes", "notes reveal");
                win.act("cancel"); win.act("reveal", "totp"); ++win.testStep; break;
            case 5:
                if (win.state.busy) return;
                if (!backend.revealed.length && !win.state.message.length) { win.act("reveal", "totp"); return; }
                win.check(/^\d{6}$/.test(backend.revealed), "current code reveal");
                win.act("focus", "false"); win.check(!backend.revealed.length, "focus hides");
                win.act("focus", "true"); win.act("filter", "All");
                win.choose("11111111-1111-4111-8111-111111111111"); ++win.testStep; break;
            case 6:
                win.check(win.compact ? detailPane.width >= win.width - 4 : credentialPane.width === 340, "pane geometry");
                surface.grabToImage(function(result) {
                    win.check(result.saveToFile("/tmp/keychain-production-" + win.testMode + ".png"), "synthetic screenshot");
                    console.log("GUI SMOKE PASS"); Qt.exit(0);
                });
                stop(); break;
            }
        }
    }
