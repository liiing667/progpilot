<?php

declare(strict_types=1);

require_once './vendor/autoload.php';

use Bartlett\Sarif\SarifLog;
use PHPUnit\Framework\TestCase;
use progpilot\Analyzer;
use progpilot\Context;
use progpilot\Outputs\SarifOutput;

final class SarifOutputTest extends TestCase
{
    private function taintStyleResult(array $overrides = []): array
    {
        return array_merge([
            'source_name' => ['$_GET["p"]'],
            'source_line' => [2],
            'source_column' => [11],
            'source_file' => ['C:\\repo\\src\\vuln.php'],
            'tainted_flow' => [
                [
                    [
                        'flow_name' => '$b',
                        'flow_line' => 3,
                        'flow_column' => 23,
                        'flow_file' => 'C:\\repo\\src\\vuln.php'
                    ],
                    [
                        'flow_name' => '$a',
                        'flow_line' => 2,
                        'flow_column' => 6,
                        'flow_file' => 'C:\\repo\\src\\vuln.php'
                    ],
                    [
                        'flow_name' => '$_GET["p"]',
                        'flow_line' => 2,
                        'flow_column' => 11,
                        'flow_file' => 'C:\\repo\\src\\vuln.php'
                    ]
                ]
            ],
            'sink_name' => 'system',
            'sink_line' => 5,
            'sink_column' => 47,
            'sink_file' => 'C:\\repo\\src\\vuln.php',
            'vuln_name' => 'command_injection',
            'vuln_cwe' => 'CWE_78',
            'vuln_id' => str_repeat('a', 64),
            'vuln_type' => 'taint-style'
        ], $overrides);
    }

    private function buildLog(array $results, ?string $analysisRoot = 'C:\\repo'): array
    {
        $sarif = new SarifOutput($results, $analysisRoot);
        $output = (string) $sarif->output();

        $decoded = json_decode($output, true);
        $this->assertIsArray($decoded, 'SARIF output must be valid JSON: ' . json_last_error_msg());

        return $decoded;
    }

    public function testOutputIsValidSarif210(): void
    {
        $decoded = $this->buildLog([$this->taintStyleResult()]);

        $this->assertSame('2.1.0', $decoded['version']);
        $this->assertSame(
            'https://json.schemastore.org/sarif-2.1.0.json',
            $decoded['$schema']
        );
        $this->assertArrayHasKey('runs', $decoded);
        $this->assertSame('progpilot', $decoded['runs'][0]['tool']['driver']['name']);
        $this->assertSame(
            ['taint-style', 'custom'],
            array_column($decoded['runs'][0]['tool']['driver']['rules'], 'id')
        );
    }

    public function testUrisAreRelativeReadablePathsWithoutBackslashesOrDriveLetter(): void
    {
        $decoded = $this->buildLog([$this->taintStyleResult()]);
        $result = $decoded['runs'][0]['results'][0];

        $sinkUri = $result['locations'][0]['physicalLocation']['artifactLocation']['uri'];
        $this->assertSame('src/vuln.php', $sinkUri);
        $this->assertDoesNotMatchRegularExpression('/[A-Za-z]:/', $sinkUri);
        $this->assertStringNotContainsString('\\', $sinkUri);

        $relatedUri = $result['relatedLocations'][0]['physicalLocation']['artifactLocation']['uri'];
        $this->assertSame('src/vuln.php', $relatedUri);

        foreach ($result['codeFlows'][0]['threadFlows'][0]['locations'] as $threadFlowLocation) {
            $uri = $threadFlowLocation['location']['physicalLocation']['artifactLocation']['uri'];
            $this->assertStringNotContainsString('\\', $uri);
            $this->assertDoesNotMatchRegularExpression('/^[A-Za-z]:/', $uri);
        }

        $this->assertStringContainsString(
            'src/vuln.php',
            $result['message']['text']
        );
        $this->assertStringNotContainsString('C:', $result['message']['text']);
    }

    public function testUrisArePercentEncoded(): void
    {
        $result = $this->taintStyleResult([
            'sink_file' => 'C:\\repo\\src dir\\a b.php',
            'source_file' => ['C:\\repo\\src dir\\a b.php']
        ]);
        $result['tainted_flow'][0][0]['flow_file'] = 'C:\\repo\\src dir\\a b.php';
        $result['tainted_flow'][0][1]['flow_file'] = 'C:\\repo\\src dir\\a b.php';
        $result['tainted_flow'][0][2]['flow_file'] = 'C:\\repo\\src dir\\a b.php';

        $decoded = $this->buildLog([$result]);
        $uri = $decoded['runs'][0]['results'][0]['locations'][0]
            ['physicalLocation']['artifactLocation']['uri'];

        $this->assertSame('src%20dir/a%20b.php', $uri);
    }

    public function testPathOutsideAnalysisRootBecomesAbsoluteFileUri(): void
    {
        $result = $this->taintStyleResult([
            'sink_file' => '/elsewhere/vuln.php',
            'source_file' => ['/elsewhere/vuln.php']
        ]);
        $result['tainted_flow'][0][0]['flow_file'] = '/elsewhere/vuln.php';
        $result['tainted_flow'][0][1]['flow_file'] = '/elsewhere/vuln.php';
        $result['tainted_flow'][0][2]['flow_file'] = '/elsewhere/vuln.php';

        $decoded = $this->buildLog([$result], '/repo');
        $uri = $decoded['runs'][0]['results'][0]['locations'][0]
            ['physicalLocation']['artifactLocation']['uri'];

        $this->assertSame('file:///elsewhere/vuln.php', $uri);
    }

    public function testCodeFlowKeepsEveryHopFromSourceToSinkInOrder(): void
    {
        $decoded = $this->buildLog([$this->taintStyleResult()]);
        $locations = $decoded['runs'][0]['results'][0]
            ['codeFlows'][0]['threadFlows'][0]['locations'];

        // 3 taint hops plus the sink, and every hop is retained (not just the
        // first location of each segment)
        $this->assertCount(4, $locations);

        $ordered = array_map(
            fn (array $threadFlowLocation): array => [
                $threadFlowLocation['executionOrder'],
                $threadFlowLocation['location']['physicalLocation']['region']['startLine'],
                $threadFlowLocation['location']['physicalLocation']['region']['startColumn'],
                $threadFlowLocation['location']['message']['text']
            ],
            $locations
        );

        $this->assertSame([
            [0, 2, 11, '$_GET["p"]'],
            [1, 2, 6, '$a'],
            [2, 3, 23, '$b'],
            [3, 5, 47, 'system']
        ], $ordered);

        $executionOrders = array_column($locations, 'executionOrder');
        $this->assertSame([0, 1, 2, 3], $executionOrders);
        $this->assertSame('taint', $locations[0]['kinds'][0]);
    }

    public function testFingerprintsAreStableAcrossPathStylesAndScans(): void
    {
        $first = $this->buildLog([$this->taintStyleResult()]);
        $second = $this->buildLog([$this->taintStyleResult()]);

        $firstFingerprint = $first['runs'][0]['results'][0]['fingerprints']['progpilotV3'];
        $secondFingerprint = $second['runs'][0]['results'][0]['fingerprints']['progpilotV3'];

        $this->assertSame($firstFingerprint, $secondFingerprint);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $firstFingerprint);

        // POSIX-style representation of the same files must yield the same identity
        $posix = $this->taintStyleResult();
        $posix['sink_file'] = '/repo/src/vuln.php';
        $posix['source_file'] = ['/repo/src/vuln.php'];
        foreach ($posix['tainted_flow'][0] as &$hop) {
            $hop['flow_file'] = '/repo/src/vuln.php';
        }
        unset($hop);

        $posixLog = $this->buildLog([$posix], '/repo');
        $this->assertSame(
            $firstFingerprint,
            $posixLog['runs'][0]['results'][0]['fingerprints']['progpilotV3']
        );

        $this->assertSame(
            str_repeat('a', 64),
            $first['runs'][0]['results'][0]['fingerprints']['progpilot/vuln-id/v1']
        );
        $this->assertArrayHasKey(
            'progpilot/sink/v1',
            $first['runs'][0]['results'][0]['partialFingerprints']
        );
    }

    public function testDuplicateFindingsAreDeduplicated(): void
    {
        $result = $this->taintStyleResult();
        $decoded = $this->buildLog([$result, $result, $result]);

        $this->assertCount(1, $decoded['runs'][0]['results']);
    }

    public function testDistinctFindingsAreKept(): void
    {
        $first = $this->taintStyleResult();
        $second = $this->taintStyleResult(['sink_line' => 9]);

        $decoded = $this->buildLog([$first, $second]);

        $this->assertCount(2, $decoded['runs'][0]['results']);
    }

    public function testCustomResultFingerprintAndRelativeUri(): void
    {
        $custom = [
            'vuln_rule' => 'DEV_IAM_AUTHENTICATED',
            'vuln_name' => 'bypass access control',
            'vuln_line' => 13,
            'vuln_column' => 1,
            'vuln_file' => 'C:\\repo\\tests\\custom\\custom1.php',
            'vuln_description' => 'bypass access control',
            'vuln_cwe' => 'CWE_285',
            'vuln_id' => str_repeat('b', 64),
            'vuln_type' => 'custom'
        ];

        $decoded = $this->buildLog([$custom]);
        $result = $decoded['runs'][0]['results'][0];

        $this->assertSame('custom', $result['ruleId']);
        $this->assertSame(
            'tests/custom/custom1.php',
            $result['locations'][0]['physicalLocation']['artifactLocation']['uri']
        );
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{64}$/',
            $result['fingerprints']['progpilotV3']
        );
    }

    public function testOutputImplementsSarifLog210(): void
    {
        $sarif = new SarifOutput([$this->taintStyleResult()], 'C:\\repo');

        $this->assertInstanceOf(SarifLog::class, $sarif->output());
    }
}

final class SarifOutputIntegrationTest extends TestCase
{
    public function testEndToEndTaintFlowProducesRelativeSourceToSinkSarif(): void
    {
        $context = new Context();
        $analyzer = new Analyzer();
        $context->inputs->setDev(true);
        $context->outputs->taintedFlow(true);
        $context->inputs->setFile('./tests/flows/flow1.php');
        $analyzer->run($context);

        $rawResults = $context->outputs->getResults();
        $this->assertNotEmpty($rawResults);

        // the plain JSON results keep their original (absolute) paths: SARIF
        // normalization must not mutate the analyzer output
        $this->assertStringContainsString(
            'tests/flows/flow1.php',
            $rawResults[0]['sink_file']
        );

        $sarif = new SarifOutput($rawResults, getcwd());
        $decoded = json_decode((string) $sarif->output(), true);
        $this->assertIsArray($decoded);

        $result = $decoded['runs'][0]['results'][0];
        $uri = $result['locations'][0]['physicalLocation']['artifactLocation']['uri'];
        $this->assertSame('tests/flows/flow1.php', $uri);

        $locations = $result['codeFlows'][0]['threadFlows'][0]['locations'];
        $this->assertGreaterThan(1, count($locations));

        $lastLocation = end($locations);
        $this->assertSame(
            $result['locations'][0]['physicalLocation']['region']['startLine'],
            $lastLocation['location']['physicalLocation']['region']['startLine']
        );

        $orders = array_column($locations, 'executionOrder');
        $this->assertSame(range(0, count($locations) - 1), $orders);

        // running the same analysis twice must produce identical identities
        $rerunContext = new Context();
        $rerunAnalyzer = new Analyzer();
        $rerunContext->inputs->setDev(true);
        $rerunContext->outputs->taintedFlow(true);
        $rerunContext->inputs->setFile('./tests/flows/flow1.php');
        $rerunAnalyzer->run($rerunContext);

        $rerun = json_decode(
            (string) (new SarifOutput($rerunContext->outputs->getResults(), getcwd()))->output(),
            true
        );

        $this->assertSame(
            array_column($decoded['runs'][0]['results'], 'fingerprints'),
            array_column($rerun['runs'][0]['results'], 'fingerprints')
        );
    }
}
