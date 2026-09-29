<?php

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/summary.php';

/** The DROP hover text lives in PHP (server page) and JS (workbench); keep them identical. */
class DropExplainerTest extends TestCase
{
    public function testWorkbenchCarriesTheSameExplainer(): void
    {
        $js = file_get_contents(dirname(__DIR__) . '/assets/js/workbench.js');
        $this->assertStringContainsString("var DROP_EXPLAINER = '" . str_replace("'", "\\'", DROP_EXPLAINER) . "';", $js);
    }

    public function testExplainerNamesSpamhausDrop(): void
    {
        $this->assertStringContainsString("Don't Route Or Peer", DROP_EXPLAINER);
    }
}
