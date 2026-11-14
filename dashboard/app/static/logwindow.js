// The logs page's window onto a source's daily log files: which lines are on
// screen, and where the next older and newer pages of /api/v1/logs/page start.
//
// The page never holds a whole file. Positions are (day, byte offset) pairs, so
// the window runs across files: a page covers bytes [start, end) of one day's
// file and names the neighbouring days that have files (prev_date, next_date).
// Past the start of a file the window continues with the previous day's tail;
// past the end, with the next day's file from its first byte.
//
// The window keeps at most `max` lines. Taking an older page drops lines from
// the bottom and moves the newer cursor back to the first line dropped, so
// scrolling down fetches it again; taking a newer page does the same at the top.
//
// Auto-scroll follows the reader: scrolling up turns it off, and reaching the
// newest line (the bottom, with nothing newer left to fetch) turns it back on.
(function (root) {
    function rowsOf(page) {
        return page.lines.map(function (line) { return { date: page.date, off: line.off }; });
    }

    function fromPage(page) {
        return {
            rows: rowsOf(page),
            start: { date: page.date, off: page.start },
            end: { date: page.date, off: page.end },
            startAtFileStart: page.at_start,
            startPrev: page.prev_date || null,
            endAtFileEnd: page.at_end,
            endNext: page.next_date || null
        };
    }

    // Nothing older anywhere: the start of the first day's file.
    function atStart(win) { return win.startAtFileStart && !win.startPrev; }

    // Nothing newer to fetch now: the end of the newest day's file.
    function atEnd(win) { return win.endAtFileEnd && !win.endNext; }

    // The request for the next older page, or null at the beginning.
    function olderRequest(win) {
        if (!win.startAtFileStart) return { date: win.start.date, before: win.start.off };
        if (win.startPrev) return { date: win.startPrev };
        return null;
    }

    // The request for the next newer page (the newest file's tail when at its end).
    function newerRequest(win) {
        if (win.endAtFileEnd && win.endNext) return { date: win.endNext, after: 0 };
        return { date: win.end.date, after: win.end.off };
    }

    function older(win, page, max) {
        var rows = rowsOf(page).concat(win.rows);
        var next = {
            rows: rows,
            start: { date: page.date, off: page.start },
            end: win.end,
            startAtFileStart: page.at_start,
            startPrev: page.prev_date || null,
            endAtFileEnd: win.endAtFileEnd,
            endNext: win.endNext
        };
        var drop = Math.max(0, rows.length - max);
        if (drop) {
            var first = rows[rows.length - drop];
            next.end = { date: first.date, off: first.off };
            next.rows = rows.slice(0, rows.length - drop);
            next.endAtFileEnd = false;
            next.endNext = null;
        }
        return { win: next, dropBottom: drop };
    }

    function newer(win, page, max) {
        var rows = win.rows.concat(rowsOf(page));
        var next = {
            rows: rows,
            start: win.start,
            end: { date: page.date, off: page.end },
            startAtFileStart: win.startAtFileStart,
            startPrev: win.startPrev,
            endAtFileEnd: page.at_end,
            endNext: page.next_date || null
        };
        var drop = Math.max(0, rows.length - max);
        if (drop) {
            var first = rows[drop];
            next.start = { date: first.date, off: first.off };
            next.rows = rows.slice(drop);
            next.startAtFileStart = false;
            next.startPrev = null;
        }
        return { win: next, dropTop: drop };
    }

    function follows(following, movedUp, atBottom, atEndOfLog) {
        if (movedUp) return false;
        if (atBottom && atEndOfLog) return true;
        return following;
    }

    function dayName(date) {
        return new Date(date + 'T12:00:00').toLocaleDateString(
            'en-US', { weekday: 'long', year: 'numeric', month: 'short', day: 'numeric' });
    }

    // The marker between the last line of one day's file and the first line of
    // the next one on screen: both days and both files, so a day with no lines
    // in between is plain to see.
    function transitionLabel(source, prevDate, date) {
        return '▲ end of ' + dayName(prevDate) + ' · ' + source + '-' + prevDate + '.log\n' +
            '▼ start of ' + dayName(date) + ' · ' + source + '-' + date + '.log';
    }

    var LogWindow = {
        fromPage: fromPage, atStart: atStart, atEnd: atEnd,
        olderRequest: olderRequest, newerRequest: newerRequest,
        older: older, newer: newer, follows: follows,
        dayName: dayName, transitionLabel: transitionLabel
    };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = LogWindow;
    } else {
        root.LogWindow = LogWindow;
    }
})(typeof window !== 'undefined' ? window : this);
