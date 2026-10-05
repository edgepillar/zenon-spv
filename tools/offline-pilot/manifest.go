package main

// The pilot selects existing tests rather than maintaining a second verifier
// or fixture server. Missing or renamed tests must not silently pass a run.
type scenario struct {
	ID       string   `json:"id"`
	Package  string   `json:"package"`
	Test     string   `json:"test"`
	Commands []string `json:"-"`
}

var scenarios = []scenario{
	{"build_identity", "internal/conformance", "TestCompiledCLIBuildIdentity", []string{"zenon-spv", "fetch-bundle"}},
	{"collect_query_resume", "internal/conformance", "TestCompiledCLIQueryWorkflow", []string{"zenon-spv", "fetch-bundle"}},
	{"query_report_consumer", "internal/conformance", "TestCompiledQueryReportConsumer", []string{"zenon-spv", "consume-query-report"}},
	{"consumer_input_descriptors", "tools/consume-query-report", "TestConsumerInputDescriptors", nil},
	{"consumer_input_fifo", "tools/consume-query-report", "TestConsumerInputFIFOOpenIsBounded", nil},
	{"compiled_query_consumer_scaling", "internal/conformance", "TestCompiledQueryConsumerScaling", []string{"zenon-spv", "consume-query-report"}},
	{"block_observer", "internal/conformance", "TestCompiledBlockObserver", []string{"zenon-spv", "consume-query-report", "observe-block"}},
	{"rpc_block_observer", "internal/conformance", "TestCompiledRPCBlockObserver", []string{"fetch-bundle", "zenon-spv", "consume-query-report", "observe-block"}},
	{"rpc_delayed_block_observer", "internal/conformance", "TestCompiledRPCObserverDelayedInclusion", []string{"fetch-bundle", "zenon-spv", "consume-query-report", "observe-block"}},
	{"rpc_selected_block_observer", "internal/conformance", "TestCompiledRPCObserverSelectedMomenta", []string{"fetch-bundle", "zenon-spv", "consume-query-report", "observe-block"}},
	{"block_observer_process_boundaries", "tools/observe-block", "TestObservationProcessBoundaries", nil},
	{"candidate_binary_export", "internal/conformance", "TestCandidateBinaryExport", nil},
	{"candidate_manifest", "tools/offline-pilot", "TestCandidateManifest", nil},
	{"pinned_operator_workflow", "internal/conformance", "TestCompiledPinnedOperatorWorkflow", []string{"zenon-spv", "fetch-bundle"}},
	{"rpc_redirect_boundary", "internal/conformance", "TestCompiledRPCRedirectBoundary", []string{"zenon-spv", "fetch-bundle"}},
	{"retention_depth_workflow", "internal/conformance", "TestCompiledRetentionDepthWorkflow", []string{"zenon-spv"}},
	{"delayed_multi_height_segment", "internal/verify", "TestRetentionSeparatesHistoryFromDepth", nil},
	{"retention_migration", "internal/verify", "TestRetentionPersistenceMigrationAndAuthorizationBeforeShrink", nil},
	{"node_delayed_inclusion", "internal/conformance", "TestNodeDelayedInclusionAcrossVersionsAndResume", nil},
	{"compiled_delayed_inclusion", "internal/conformance", "TestCompiledDelayedInclusionWorkflow", []string{"zenon-spv", "fetch-bundle"}},
	{"retained_capacity_workloads", "internal/conformance", "TestRetainedCapacityWorkloads", nil},
	{"bounded_state_reader", "internal/verify", "TestSizedStateReadContract", nil},
	{"bounded_bundle_reader", "internal/proof", "TestSizedBundleReadContract", nil},
	{"node_content_scaling", "internal/conformance", "TestNodeContentScaling", nil},
	{"compiled_content_scaling", "internal/conformance", "TestCompiledContentScalingWorkflow", []string{"zenon-spv"}},
	{"process_memory_accounting", "internal/conformance", "TestProcessMemoryAccounting", nil},
	{"content_hash_serialization", "internal/chain", "TestMomentumContentHashSerializationContract", nil},
	{"signed_envelope_serialization", "internal/chain", "TestSignedEnvelopeHashSerializationContract", nil},
	{"state_inspection", "internal/conformance", "TestCompiledCLIStateInspection", []string{"zenon-spv"}},
	{"writer_exclusion", "internal/conformance", "TestCompiledCLIStateWriterExclusion", []string{"zenon-spv"}},
	{"watch_events", "internal/conformance", "TestCompiledWatchJSONEvents", []string{"zenon-spv"}},
	{"single_step_watch", "internal/conformance", "TestCompiledWatchOnceJSONEvents", []string{"zenon-spv"}},
	{"peer_faults", "internal/conformance", "TestOfflineWatchPeerFaults", nil},
	{"activation_and_resume", "internal/conformance", "TestNodeTransitionProfileAndResume", nil},
	{"captured_policy", "internal/conformance", "TestNodeTransitionRetainedPolicyCannotBeDropped", nil},
	{"proof_byte_limits", "internal/conformance", "TestCompiledCLIProofByteBounds", []string{"zenon-spv"}},
	{"bundle_count_limits", "internal/conformance", "TestCompiledCLIBundleCountBounds", []string{"zenon-spv"}},
	{"schedule_input", "internal/conformance", "TestCompiledCLIRejectsAmbiguousScheduleBeforeState", []string{"zenon-spv"}},
	{"schedule_export", "internal/conformance", "TestCompiledScheduleExportAndVerification", []string{"derive-producer-schedule", "zenon-spv"}},
	{"checkpoint_network_binding", "internal/conformance", "TestCompiledCheckpointRefusesNonMainnetCorpus", []string{"derive-checkpoints"}},
	{"genesis_pinning", "internal/conformance", "TestCompiledGenesisRequiresExpectedHashAndEveryPeer", []string{"verify-mainnet-genesis"}},
	{"custom_genesis_observation", "internal/conformance", "TestCompiledNodeDerivedCustomGenesis", []string{"verify-mainnet-genesis"}},
	{"save_failure_events", "internal/syncer", "TestWatchJSONEventsRespectVerificationAndPersistence", nil},
	{"save_recovery", "internal/syncer", "TestWatchJSONSaveRecoveryRetainsAttemptBoundaries", nil},
	{"event_delivery_failure", "internal/syncer", "TestWatchJSONOutputFailureStopsWithoutRetry", nil},
	{"request_limits", "internal/syncer", "TestTickCapsRPCRequestsByVerifierPolicy", nil},
	{"producer_coverage_gap", "internal/verify", "TestVerifyHeadersWithOptions_RequiredUnknownHeightRefuses", nil},
	{"retained_producer_coverage_gap", "internal/verify", "TestAuthorizeRetainedWindow_RequiredRefusesUncoveredHeight", nil},
	{"native_writer_lock", "internal/statelock", "TestExclusiveStateLockPreservesFilesAndReusesInode", nil},
	{"process_lock_release", "internal/statelock", "TestStateLockReleasedOnProcessExitOrKill", nil},
}

const modulePath = "github.com/0x3639/zenon-spv"
const binaryMarker = "offline-pilot-binary "

var corpusPaths = []string{
	"internal/testdata/conformance/momentum-v1-v2.json",
	"internal/testdata/conformance/account-amounts.json",
	"internal/testdata/conformance/account-segments.json",
	"internal/testdata/conformance/contract-batches.json",
	"internal/testdata/conformance/delayed-inclusion.json",
	"internal/testdata/conformance/content-scaling.json",
	"internal/testdata/conformance/historical-testnet-genesis.json",
}
