/**
 * Parity test for assets/js/summary.js against the real PHP
 * includes/summary.php's build_summary() (design doc: "Summary line uses
 * the same rules as includes/summary.php; port build_summary to JS and
 * prove parity with a fixture").
 *
 * Rather than re-deriving expected output by hand (which would only prove
 * the JS port agrees with itself), this shells out to `php` and runs the
 * real build_summary() on the same fixture rows, then diffs the JSON.
 * Skips itself gracefully if `php` isn't on PATH.
 */

'use strict';

var path = require('path');
var childProcess = require('child_process');
var Summary = require('../../assets/js/summary.js');

function phpAvailable() {
  var res = childProcess.spawnSync('php', ['-v']);
  return res.status === 0;
}

function phpBuildSummary(rows) {
  var summaryPhp = path.resolve(__dirname, '../../includes/summary.php');
  var script = [
    'require ' + JSON.stringify(summaryPhp) + ';',
    '$rows = json_decode(file_get_contents("php://stdin"), true);',
    'echo json_encode(build_summary($rows));'
  ].join(' ');
  var res = childProcess.spawnSync('php', ['-r', script], {
    input: JSON.stringify(rows),
    encoding: 'utf8'
  });
  if (res.status !== 0) {
    throw new Error('php build_summary() failed: ' + res.stderr);
  }
  return JSON.parse(res.stdout);
}

var maybeDescribe = phpAvailable() ? describe : describe.skip;

maybeDescribe('summary.js parity with includes/summary.php', () => {
  var fixtures = [
    { name: 'empty', rows: [] },
    {
      name: 'mixed categories, ASNs and DROP',
      rows: [
        { category: 'cloud', asn: 'AS14061', asn_org: 'DigitalOcean, LLC', drop: false },
        { category: 'cloud', asn: 'AS14061', asn_org: 'DigitalOcean, LLC', drop: false },
        { category: 'scanning', asn: 'AS398324', asn_org: 'Censys, Inc.', drop: true },
        { category: 'vpn', asn: 'AS9009', asn_org: 'M247 Europe SRL', drop: false },
        { category: 'unknown', asn: '', asn_org: '', drop: false },
      ],
    },
    {
      name: 'single row, singular grammar',
      rows: [{ category: 'residential', asn: 'AS1', asn_org: 'Org', drop: false }],
    },
    {
      name: 'more than 3 ASNs, top-3 only',
      rows: [
        { category: 'cloud', asn: 'AS1', asn_org: 'One', drop: false },
        { category: 'cloud', asn: 'AS1', asn_org: 'One', drop: false },
        { category: 'cloud', asn: 'AS1', asn_org: 'One', drop: false },
        { category: 'cloud', asn: 'AS2', asn_org: 'Two', drop: false },
        { category: 'cloud', asn: 'AS2', asn_org: 'Two', drop: false },
        { category: 'cloud', asn: 'AS3', asn_org: 'Three', drop: false },
        { category: 'cloud', asn: 'AS4', asn_org: 'Four', drop: false },
      ],
    },
    {
      name: 'unrecognized category falls back to unknown',
      rows: [{ category: 'totally-bogus', asn: '', asn_org: '', drop: false }],
    },
  ];

  fixtures.forEach(function (fixture) {
    test(fixture.name, () => {
      var jsResult = Summary.buildSummary(fixture.rows);
      var phpResult = phpBuildSummary(fixture.rows);
      expect(jsResult).toEqual(phpResult);
    });
  });
});
