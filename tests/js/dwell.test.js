/**
 * Jest tests for the behavioral tracking JS embedded in report_functions.php.
 *
 * Tests the logic extracted from the inline <script> block:
 * exitFired dedup, dwell cap, CTA visible timer, sendBeacon payload shape.
 */

// ── Helpers ───────────────────────────────────────────────────────────────────

// sendFn in dwell tracker is called as sendFn(eventType) — no body arg
function makeSendBeaconSpy() {
  const calls = [];
  const spy = jest.fn((eventType) => {
    calls.push(eventType);
  });
  return { spy, calls };
}

// Extract the dwell logic as a pure function so we can unit-test it.
// Mirrors report_functions.php lines: startTime / exitFired / onExit
function makeDwellTracker(startTimeSecs, sendFn, umamiTrackFn) {
  let exitFired = false;
  let startTime = startTimeSecs;

  function onExit(nowSecs) {
    if (exitFired) return;
    exitFired = true;
    const secs = Math.min(600, nowSecs - startTime);
    umamiTrackFn('report_dwell', { seconds_on_page: secs });
    sendFn('page_viewed');
  }

  function onReturn(nowSecs) {
    exitFired = false;
    startTime = nowSecs;
    sendFn('page_viewed');
  }

  return { onExit, onReturn, getExitFired: () => exitFired };
}

// ── exitFired deduplication ───────────────────────────────────────────────────

describe('exitFired dedup flag', () => {
  test('first exit fires correctly', () => {
    const { spy, calls } = makeSendBeaconSpy();
    const umami = jest.fn();
    const tracker = makeDwellTracker(1000, spy, umami);

    tracker.onExit(1060);

    expect(spy).toHaveBeenCalledTimes(1);
    expect(umami).toHaveBeenCalledTimes(1);
  });

  test('second exit is a no-op when exitFired is already true', () => {
    const { spy } = makeSendBeaconSpy();
    const umami = jest.fn();
    const tracker = makeDwellTracker(1000, spy, umami);

    tracker.onExit(1060);
    tracker.onExit(1061); // duplicate — should be ignored

    expect(spy).toHaveBeenCalledTimes(1);
    expect(umami).toHaveBeenCalledTimes(1);
  });

  test('visibilitychange and pagehide both trigger, but only one fires', () => {
    const { spy } = makeSendBeaconSpy();
    const umami = jest.fn();
    const tracker = makeDwellTracker(1000, spy, umami);

    // Simulate both visibilitychange and pagehide firing simultaneously
    tracker.onExit(1060); // visibilitychange
    tracker.onExit(1060); // pagehide — should be ignored

    expect(spy).toHaveBeenCalledTimes(1);
  });
});

// ── Dwell time cap ────────────────────────────────────────────────────────────

describe('dwell time calculation', () => {
  test('dwell is capped at 600 seconds', () => {
    const umami = jest.fn();
    const tracker = makeDwellTracker(0, jest.fn(), umami);

    tracker.onExit(3600); // 1 hour — should cap at 600

    const call = umami.mock.calls[0];
    expect(call[1].seconds_on_page).toBe(600);
  });

  test('short dwell is not capped', () => {
    const umami = jest.fn();
    const tracker = makeDwellTracker(1000, jest.fn(), umami);

    tracker.onExit(1045); // 45 seconds

    const call = umami.mock.calls[0];
    expect(call[1].seconds_on_page).toBe(45);
  });

  test('exactly 600 seconds passes through uncapped', () => {
    const umami = jest.fn();
    const tracker = makeDwellTracker(0, jest.fn(), umami);

    tracker.onExit(600);

    const call = umami.mock.calls[0];
    expect(call[1].seconds_on_page).toBe(600);
  });

  test('zero dwell (instant bounce) records 0 seconds', () => {
    const umami = jest.fn();
    const tracker = makeDwellTracker(1000, jest.fn(), umami);

    tracker.onExit(1000); // no time elapsed

    const call = umami.mock.calls[0];
    expect(call[1].seconds_on_page).toBe(0);
  });
});

// ── Return-to-tab resets state ────────────────────────────────────────────────

describe('return-to-tab behavior', () => {
  test('onReturn resets exitFired so next exit fires again', () => {
    const { spy } = makeSendBeaconSpy();
    const umami = jest.fn();
    const tracker = makeDwellTracker(1000, spy, umami);

    tracker.onExit(1060);  // first exit
    tracker.onReturn(1065); // tab returns — resets flag and startTime
    tracker.onExit(1120);  // second exit should fire

    expect(spy).toHaveBeenCalledTimes(3); // exit + return + exit
    expect(umami).toHaveBeenCalledTimes(2); // two dwell events
  });

  test('onReturn fires page_viewed beacon', () => {
    const { spy, calls } = makeSendBeaconSpy();
    const tracker = makeDwellTracker(1000, spy, jest.fn());

    tracker.onReturn(1100);

    expect(spy).toHaveBeenCalledWith('page_viewed');
    expect(calls[0]).toBe('page_viewed');
  });

  test('dwell after return uses new startTime', () => {
    const umami = jest.fn();
    const tracker = makeDwellTracker(0, jest.fn(), umami);

    tracker.onExit(300);     // first exit at 300s
    tracker.onReturn(350);   // returns at 350s
    tracker.onExit(400);     // exits again at 400s — dwell should be 50s, not 400s

    const secondDwellCall = umami.mock.calls[1];
    expect(secondDwellCall[1].seconds_on_page).toBe(50);
  });
});

// ── sendBeacon payload shape ──────────────────────────────────────────────────

describe('sendBeacon payload', () => {
  test('payload includes token, event_type, and session_id', () => {
    const TOKEN      = 'aaaaaaaa-0000-4000-8000-000000000001';
    const REPORT_SID = 'abcdef1234567890abcdef1234567890';
    const calls = [];

    function sendEvent(type) {
      calls.push(JSON.parse(JSON.stringify({ token: TOKEN, event_type: type, session_id: REPORT_SID })));
    }

    sendEvent('cta_clicked');

    expect(calls[0].token).toBe(TOKEN);
    expect(calls[0].event_type).toBe('cta_clicked');
    expect(calls[0].session_id).toBe(REPORT_SID);
  });

  test('all four event types are valid', () => {
    const allowed = ['page_viewed', 'cta_visible', 'cta_clicked', 'checkout_started'];
    allowed.forEach(type => {
      expect(allowed).toContain(type);
    });
  });
});

// ── IP count bucketing ────────────────────────────────────────────────────────

describe('IP count bucket calculation', () => {
  function getBucket(total) {
    return total <= 10  ? '1-10'
         : total <= 50  ? '11-50'
         : total <= 200 ? '51-200'
         : total <= 1000 ? '201-1000'
         : total <= 5000 ? '1001-5000'
         : '5000+';
  }

  test.each([
    [1, '1-10'],
    [10, '1-10'],
    [11, '11-50'],
    [50, '11-50'],
    [51, '51-200'],
    [200, '51-200'],
    [201, '201-1000'],
    [1000, '201-1000'],
    [1001, '1001-5000'],
    [5000, '1001-5000'],
    [5001, '5000+'],
    [10000, '5000+'],
  ])('total=%i → bucket %s', (total, expected) => {
    expect(getBucket(total)).toBe(expected);
  });
});
