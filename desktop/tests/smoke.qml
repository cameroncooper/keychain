    property int testStep: 0
    property int testTries: 0
    property var testFirst: null
    readonly property string first: "11111111-1111-4111-8111-111111111111"
    readonly property string second: "22222222-2222-4222-8222-222222222222"
    function check(condition, label) {
        if (!condition) { console.error("GUI SMOKE FAIL: " + label); Qt.exit(1); }
    }
    function grab(name, then) {
        surface.grabToImage(function(result) {
            win.check(result.saveToFile("/tmp/keychain-production-" + name + ".png"), "synthetic screenshot " + name);
            then();
        });
    }
    Timer {
        interval: 250
        running: true
        repeat: true
        onTriggered: {
            if (++win.testTries > 120) { console.error("GUI SMOKE TIMEOUT step " + win.testStep); Qt.exit(1); return; }
            switch (win.testStep) {
            case 0:
                if (win.testMode === "narrow") win.width = 640;
                if (win.items.length !== 2 || !win.settled) return;
                console.log("window active: " + win.active);
                win.check(win.tokens.background === (win.testMode === "light" ? "#f4f3ef" : "#16161a"), "explicit palette");
                win.check(win.font.pixelSize === 13 && search.font.pixelSize === 14, "typography");
                win.check(categoryPane.width === (win.compact ? 52 : 190), "sidebar or rail");
                win.check(Theme.radius === 0 && Theme.red.a === 1 && Theme.light === (win.testMode === "light"), "derived theme");
                win.check(String(Theme.accentText) === (win.testMode === "light" ? "#ffffff" : "#000000"), "text on the accent");
                win.check(win.authMode === "per-operation", "authorization mode");
                win.check(win.counts.All === 2 && win.counts.Code === 1 && win.counts.Passkey === 0, "category counts");
                win.check(win.state.refreshedAt > 0, "refresh time");
                win.check(credentialPane.view.count === 2, "list model");
                win.check(search.focus, "opens in search");
                win.testFirst = credentialPane.view.itemAtIndex(1);
                search.text = "other"; ++win.testStep; break;
            case 1:
                if (win.items.length !== 1) return;  // after the search delay
                // The surviving row keeps its delegate: the model changed in place.
                win.check(credentialPane.view.count === 1 && credentialPane.view.itemAtIndex(0) === win.testFirst, "rows update in place");
                win.check(win.selected && win.selected.id === win.second, "selection follows the search");
                search.text = "nothing at all"; ++win.testStep; break;
            case 2:
                if (win.items.length !== 0) return;
                win.check(credentialPane.emptyTitle === "Nothing matches “nothing at all”", "no-match wording");
                win.dismiss();  // Escape: clears the search and returns to the list
                win.check(search.text === "", "escape clears search");
                ++win.testStep; break;
            case 3:
                if (win.items.length !== 2) return;
                credentialPane.moveTo(0);
                win.check(win.selected.id === win.first && credentialPane.view.currentIndex === 0, "arrow selects");
                credentialPane.moveTo(5);
                win.check(win.selected.id === win.second, "cursor stops at the end");
                credentialPane.moveTo(0);
                if (win.active) {
                    credentialPane.focusView();
                    win.moveKeyboard(1);
                    win.check(win.compact ? win.holds(categoryPane, win.activeFocusItem) : win.holds(detailPane, win.activeFocusItem), "tab to the next region");
                    if (!win.compact) {
                        win.moveKeyboard(1);
                        win.check(win.holds(detailPane, win.activeFocusItem) && win.activeFocusItem.objectName !== "primaryAction", "tab through the details");
                        win.moveKeyboard(-1);
                    }
                    win.moveKeyboard(-1);
                    win.check(win.holds(credentialPane, win.activeFocusItem), "shift+tab back to the list");
                }
                win.filter("Code");
                win.check(win.items.length === 1, "code filter");
                win.act("focus", "true");
                win.check(detailPane.primaryField === "password", "primary action is the password");
                win.activate(win.selected.id);  // ⏎: the main action (wide) or details (narrow)
                if (win.compact) {
                    win.check(win.detailsOpen && topBar.canGoBack, "narrow opens details");
                    detailPane.runPrimary();
                }
                win.check(win.state.pendingField === "password" || backend.revealed.length > 0, "reveal started");
                ++win.testStep; break;
            case 4:
                if (win.state.busy) return;
                win.check(backend.revealed === "synthetic-password", "password reveal");
                win.check(win.state.hidesIn > 25 && win.state.hidesIn <= 30 && win.state.pendingField === null, "reveal lifetime");
                win.check(!backend.snapshot.includes("synthetic-password") && !backend.rows.includes("synthetic-password"), "metadata isolation");
                win.dismiss();
                win.check(!backend.revealed.length, "escape hides");
                win.act("select", win.first);
                win.act("reveal", "notes"); win.act("cancel"); ++win.testStep; break;
            case 5:
                win.check(!backend.revealed.length, "cancel drops late result");
                win.act("reveal", "notes"); ++win.testStep; break;
            case 6:
                if (win.state.busy) return;
                win.check(backend.revealed === "synthetic-notes", "notes reveal");
                win.act("cancel"); win.act("reveal", "totp"); ++win.testStep; break;
            case 7:
                if (win.state.busy) return;
                if (!backend.revealed.length && !win.state.message.length) { win.act("reveal", "totp"); return; }
                win.check(/^\d{6}$/.test(backend.revealed), "current code reveal");
                win.act("focus", "false"); win.check(!backend.revealed.length, "focus hides");
                win.act("focus", "true");
                // The menu, help and a username copy, with no secret involved.
                accountMenu.show(null, Qt.point(20, 20));
                win.check(accountMenu.visible, "account menu");
                accountMenu.close();
                win.helpOpen = true;
                win.check(help.visible && win.shortcuts.length > 8, "shortcut sheet");
                win.dismiss();
                win.check(!win.helpOpen, "escape closes help");
                win.copyUsername();
                win.check(win.notice === "Username copied", "copy username");
                win.dismiss();
                // Unlock sessions: locked shows nothing but the unlock view.
                win.authMode = "locked";
                win.check(unlockView.visible && !credentialPane.visible && !categoryPane.visible && !detailPane.visible, "locked shows nothing");
                win.check(win.selected === null && topBar.crumbs.length === 1 && !topBar.canSearch, "locked hides metadata");
                ++win.testStep; break;
            case 8:
                stop();
                win.grab(win.testMode + "-locked", function() { win.testStep = 9; start(); });
                break;
            case 9:
                win.authMode = "unlocked";
                win.check(!unlockView.visible && topBar.showLock, "unlocked offers lock");
                win.check(!detailPane.asksFingerprint, "unlocked reveals without a prompt label");
                win.authMode = "per-operation";
                win.filter("All");
                win.choose(win.first);
                win.act("reveal", "password"); ++win.testStep; break;
            case 10:
                if (win.state.busy) return;
                win.check(backend.revealed === "synthetic-password", "second password reveal");
                win.check(win.compact ? detailPane.width >= win.width - Theme.rail - 4 : credentialPane.width === 340, "pane geometry");
                stop();
                win.grab(win.testMode + "-revealed", function() {
                    win.act("cancel");
                    win.grab(win.testMode, function() { console.log("GUI SMOKE PASS"); Qt.exit(0); });
                });
                break;
            }
        }
    }
