<?php

namespace progpilot\Outputs;

use Bartlett\Sarif\Definition\Message;
use Bartlett\Sarif\Definition\PropertyBag;
use Bartlett\Sarif\Definition\Run;
use Bartlett\Sarif\Definition\ToolComponent;
use Bartlett\Sarif\Definition\Tool;
use Bartlett\Sarif\Definition\Result;
use Bartlett\Sarif\Definition\Location;
use Bartlett\Sarif\Definition\ArtifactLocation;
use Bartlett\Sarif\Definition\PhysicalLocation;
use Bartlett\Sarif\Definition\ThreadFlowLocation;
use Bartlett\Sarif\Definition\Region;
use Bartlett\Sarif\Definition\ThreadFlow;
use Bartlett\Sarif\Definition\CodeFlow;
use Bartlett\Sarif\Definition\ReportingDescriptor;
use Bartlett\Sarif\Definition\MultiformatMessageString;
use Bartlett\Sarif\SarifLog;

class SarifOutput
{
    private $progpilotResults;
    private $analysisRoot;

    public function __construct($progpilotResults, ?string $analysisRoot = null)
    {
        $this->progpilotResults = $progpilotResults;
        $this->analysisRoot = $this->normalizeFilesystemPath(
            $analysisRoot ?? (getcwd() ?: DIRECTORY_SEPARATOR)
        );
    }

    private function createRules(): array
    {
        $rules = [
            [
                'id' => 'taint-style',
                'description' => 'https://github.com/designsecurity/progpilot/blob/master/docs/SPECIFY_ANALYSIS.md'
            ],
            [
                'id' => 'custom',
                'description' => 'https://github.com/LioTree/progpilot/blob/master/docs/CUSTOM_ANALYSIS.md'
            ]
        ];

        return array_map(function ($rule) {
            $reportingDescriptor = new ReportingDescriptor();
            $reportingDescriptor->setId($rule['id']);
            $message = new MultiformatMessageString();
            $message->setText($rule['description']);
            $reportingDescriptor->setShortDescription($message);
            return $reportingDescriptor;
        }, $rules);
    }

    private function createTool(): Tool
    {
        $driver = new ToolComponent();
        $driver->setName('progpilot');
        $driver->setInformationUri('https://github.com/designsecurity/progpilot');
        $driver->addRules($this->createRules());

        $tool = new Tool();
        $tool->setDriver($driver);
        return $tool;
    }

    private function createResult(array $progpilotResult): Result
    {
        $result = new Result();
        $result->setRuleId($progpilotResult['vuln_type']);

        if ($progpilotResult['vuln_type'] === 'taint-style') {
            $sinkUri = $this->relativeUri($progpilotResult['sink_file']);

            $message = new Message();
            $message->setText(
                "A vulnerability of type {$progpilotResult['vuln_name']} exists at " .
                    "{$progpilotResult['sink_name']} in file {$sinkUri} " .
                    "at line {$progpilotResult['sink_line']}."
            );
            $result->setMessage($message);

            $propertyBag = new PropertyBag();
            $propertyBag->addProperty('vuln_cwe', $progpilotResult['vuln_cwe']);
            $propertyBag->addProperty('vuln_id', $progpilotResult['vuln_id']);
            $propertyBag->addProperty('vuln_name', $progpilotResult['vuln_name']);
            $result->setProperties($propertyBag);

            $location = $this->createLocation(
                $sinkUri,
                $progpilotResult['sink_line'],
                $progpilotResult['sink_column'],
                $progpilotResult['sink_name']
            );
            $result->addLocations([$location]);

            $sourceUris = [];
            $relatedLocations = [];
            foreach ($progpilotResult['source_file'] as $index => $sourceFile) {
                $sourceUri = $this->relativeUri($sourceFile);
                $sourceUris[] = $sourceUri;
                $relatedLocation = $this->createLocation(
                    $sourceUri,
                    $progpilotResult['source_line'][$index],
                    $progpilotResult['source_column'][$index],
                    $progpilotResult['source_name'][$index]
                );
                $relatedLocations[] = $relatedLocation;
            }
            $result->addRelatedLocations($relatedLocations);

            if (isset($progpilotResult['tainted_flow'])) {
                $codeFlows = [];
                foreach ($progpilotResult['tainted_flow'] as $flow) {
                    $threadFlowLocations = [];
                    $executionOrder = 0;

                    // progpilot stores each segment from the sink back to its source:
                    // reverse it so the thread flow reads source -> ... -> sink.
                    foreach (array_reverse($flow) as $hop) {
                        $threadFlowLocation = new ThreadFlowLocation();
                        $threadFlowLocation->setLocation(
                            $this->createLocation(
                                $this->relativeUri($hop['flow_file']),
                                $hop['flow_line'],
                                $hop['flow_column'],
                                $hop['flow_name']
                            )
                        );
                        $threadFlowLocation->setExecutionOrder($executionOrder++);
                        $threadFlowLocation->addKinds(['taint']);
                        $threadFlowLocations[] = $threadFlowLocation;
                    }

                    $sinkFlowLocation = new ThreadFlowLocation();
                    $sinkFlowLocation->setLocation($location);
                    $sinkFlowLocation->setExecutionOrder($executionOrder);
                    $sinkFlowLocation->addKinds(['taint']);
                    $sinkFlowLocation->setImportance('essential');
                    $threadFlowLocations[] = $sinkFlowLocation;

                    $threadFlow = new ThreadFlow();
                    $threadFlow->addLocations($threadFlowLocations);
                    $codeFlow = new CodeFlow();
                    $codeFlow->addThreadFlows([$threadFlow]);
                    $codeFlows[] = $codeFlow;
                }
                if (count($codeFlows) > 0) {
                    $result->addCodeFlows($codeFlows);
                }
            }

            $fingerprint = $this->fingerprint(
                $progpilotResult['vuln_type'],
                $sinkUri,
                $progpilotResult['sink_line'],
                $progpilotResult['sink_column'],
                $sourceUris,
                $this->canonicalTaintFlow($progpilotResult),
                $progpilotResult['vuln_name']
            );
            $result->addFingerprints([
                'progpilotV3' => $fingerprint,
                'progpilot/vuln-id/v1' => $progpilotResult['vuln_id']
            ]);
            $result->addPartialFingerprints([
                'progpilot/sink/v1' => hash(
                    'sha256',
                    $progpilotResult['vuln_type'] . '|' . $sinkUri . '|' .
                        $progpilotResult['sink_line'] . '|' . $progpilotResult['sink_column']
                )
            ]);
        } elseif ($progpilotResult['vuln_type'] === 'custom') {
            $vulnUri = $this->relativeUri($progpilotResult['vuln_file']);

            $message = new Message();
            $message->setText($progpilotResult['vuln_description']);
            $result->setMessage($message);

            $propertyBag = new PropertyBag();
            $propertyBag->addProperty('vuln_cwe', $progpilotResult['vuln_cwe']);
            $propertyBag->addProperty('vuln_id', $progpilotResult['vuln_id']);
            $propertyBag->addProperty('vuln_name', $progpilotResult['vuln_name']);
            $propertyBag->addProperty('vuln_rule', $progpilotResult['vuln_rule']);
            $result->setProperties($propertyBag);

            $location = $this->createLocation(
                $vulnUri,
                $progpilotResult['vuln_line'],
                $progpilotResult['vuln_column'],
                $progpilotResult['vuln_name']
            );
            $result->addLocations([$location]);

            $fingerprint = $this->fingerprint(
                $progpilotResult['vuln_type'],
                $vulnUri,
                $progpilotResult['vuln_line'],
                $progpilotResult['vuln_column'],
                [],
                [],
                $progpilotResult['vuln_rule']
            );
            $result->addFingerprints([
                'progpilotV3' => $fingerprint,
                'progpilot/vuln-id/v1' => $progpilotResult['vuln_id']
            ]);
            $result->addPartialFingerprints([
                'progpilot/location/v1' => hash(
                    'sha256',
                    $progpilotResult['vuln_type'] . '|' . $vulnUri . '|' .
                        $progpilotResult['vuln_line'] . '|' . $progpilotResult['vuln_column']
                )
            ]);
        }

        return $result;
    }

    private function createLocation(string $uri, int $line, int $column, string $name): Location
    {
        $artifactLocation = new ArtifactLocation();
        $artifactLocation->setUri($uri);

        $region = new Region();
        $region->setStartLine($line);
        $region->setStartColumn($column);

        $physicalLocation = new PhysicalLocation();
        $physicalLocation->setArtifactLocation($artifactLocation);
        $physicalLocation->setRegion($region);

        $location = new Location();
        $location->setPhysicalLocation($physicalLocation);

        $message = new Message();
        $message->setText($name);
        $location->setMessage($message);

        return $location;
    }

    /**
     * Normalizes an OS path (Windows or POSIX) into a forward-slash path
     * without drive letter, with "." and ".." segments resolved lexically.
     */
    private function normalizeFilesystemPath(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $path = preg_replace('#^[a-zA-Z]:[|/]#', '/', $path);
        $path = preg_replace('#^[a-zA-Z]:#', '', $path);

        $isAbsolute = (strncmp($path, '/', 1) === 0);
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if (count($segments) > 0 && end($segments) !== '..') {
                    array_pop($segments);
                } elseif (!$isAbsolute) {
                    $segments[] = '..';
                }
                continue;
            }
            $segments[] = $segment;
        }

        $normalized = implode('/', $segments);
        if ($isAbsolute) {
            return '/' . $normalized;
        }
        return $normalized;
    }

    private function relativeUri(string $path): string
    {
        $normalized = $this->normalizeFilesystemPath($path);

        if (strncmp($normalized, '/', 1) === 0) {
            $root = rtrim($this->analysisRoot, '/');
            if ($root !== '' && strncmp($normalized, $root . '/', strlen($root) + 1) === 0) {
                $normalized = substr($normalized, strlen($root) + 1);
            } else {
                // outside the analysis root: emit an absolute file URI so the
                // location stays resolvable without leaking backslashes or a
                // Windows drive letter
                return 'file://' . implode(
                    '/',
                    array_map('rawurlencode', explode('/', $normalized))
                );
            }
        }

        return implode('/', array_map('rawurlencode', explode('/', $normalized)));
    }

    private function canonicalTaintFlow(array $progpilotResult): array
    {
        if (!isset($progpilotResult['tainted_flow'])) {
            return [];
        }

        $canonical = [];
        foreach ($progpilotResult['tainted_flow'] as $flow) {
            $segment = [];
            foreach (array_reverse($flow) as $hop) {
                $segment[] = [
                    'file' => $this->relativeUri($hop['flow_file']),
                    'line' => $hop['flow_line'],
                    'column' => $hop['flow_column'],
                    'name' => $hop['flow_name']
                ];
            }
            $canonical[] = $segment;
        }

        return $canonical;
    }

    private function fingerprint(
        string $ruleId,
        string $sinkUri,
        int $sinkLine,
        int $sinkColumn,
        array $sourceUris,
        array $canonicalTaintFlow,
        string $discriminator
    ): string {
        $sources = $sourceUris;
        sort($sources);

        $identity = [
            'version' => 3,
            'rule' => $ruleId,
            'sink' => [$sinkUri, $sinkLine, $sinkColumn],
            'sources' => $sources,
            'flows' => $canonicalTaintFlow,
            'discriminator' => $discriminator
        ];

        return hash('sha256', json_encode($identity, JSON_UNESCAPED_SLASHES));
    }

    public function output(): SarifLog
    {
        $run = new Run();
        $run->setTool($this->createTool());

        $results = [];
        $seenFingerprints = [];
        foreach ($this->progpilotResults as $progpilotResult) {
            $result = $this->createResult($progpilotResult);
            $fingerprints = $result->jsonSerialize()['fingerprints'] ?? [];
            $fingerprint = $fingerprints['progpilotV3'] ?? null;

            // repeated scans must report the same logical finding only once
            if ($fingerprint !== null && isset($seenFingerprints[$fingerprint])) {
                continue;
            }
            if ($fingerprint !== null) {
                $seenFingerprints[$fingerprint] = true;
            }
            $results[] = $result;
        }

        $run->addResults($results);

        return new SarifLog([$run]);
    }
}
