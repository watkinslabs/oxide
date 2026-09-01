use super::*;
    fn args() -> SyscallArgs { SyscallArgs { a0: u64::MAX, a1: 0x1122_3344_5566_7788, a2: 3, a3: 4, a4: 5, a5: 6 } }

    #[test]
    fn every_defined_service_decodes_without_argument_loss() {
        let input = args();
        assert_eq!(decode(0, input).unwrap().service, NtService::AllocateVirtualMemory);
        assert_eq!(decode(1, input).unwrap().service, NtService::FreeVirtualMemory);
        assert_eq!(decode(2, input).unwrap().service, NtService::ProtectVirtualMemory);
        let call = decode(3, input).unwrap();
        assert_eq!(call.service, NtService::QueryVirtualMemory);
        assert_eq!(call.args, input);
        assert_eq!(decode(4, input).unwrap().service, NtService::TerminateProcess);
        assert_eq!(decode(5, input).unwrap().service, NtService::CreateEvent);
        assert_eq!(decode(8, input).unwrap().service, NtService::ResetEvent);
        assert_eq!(decode(16, input).unwrap().service, NtService::QueryDirectoryFile);
        assert_eq!(decode(17, input).unwrap().service, NtService::WaitForMultipleObjects);
        assert_eq!(decode(18, input).unwrap().service, NtService::CreateSection);
        assert_eq!(decode(19, input).unwrap().service, NtService::MapViewOfSection);
        assert_eq!(decode(20, input).unwrap().service, NtService::UnmapViewOfSection);
        assert_eq!(decode(21, input).unwrap().service, NtService::QueryInformationProcess);
        assert_eq!(decode(22, input).unwrap().service, NtService::CreateThreadEx);
        assert_eq!(decode(23, input).unwrap().service, NtService::TerminateThread);
        assert_eq!(decode(24, input).unwrap().service, NtService::QueryInformationThread);
        assert_eq!(decode(25, input).unwrap().service, NtService::AllocateHeap);
        assert_eq!(decode(26, input).unwrap().service, NtService::FreeHeap);
        assert_eq!(decode(27, input).unwrap().service, NtService::CreateWindow);
        assert_eq!(decode(28, input).unwrap().service, NtService::DestroyWindow);
        assert_eq!(decode(29, input).unwrap().service, NtService::PostMessage);
        assert_eq!(decode(30, input).unwrap().service, NtService::PeekMessage);
        assert_eq!(decode(31, input).unwrap().service, NtService::GetMessage);
        assert_eq!(decode(36, input).unwrap().service, NtService::CreateSemaphore); assert_eq!(decode(37, input).unwrap().service, NtService::ReleaseSemaphore); assert_eq!(decode(38, input).unwrap().service, NtService::ExecuteWithCatalog); assert_eq!(decode(39, input).unwrap().service, NtService::CreateMutant); assert_eq!(decode(40, input).unwrap().service, NtService::ReleaseMutant); assert_eq!(decode(41, input).unwrap().service, NtService::QueryMutant); assert!(matches!(decode_loader(decode(38, SyscallArgs { a0: 0x1000, ..input }).unwrap()), Ok(NtLoaderCall::ExecuteWithCatalog { .. })));
        assert_eq!(decode(32, input).unwrap().service, NtService::DefaultWindowProc);
        assert_eq!(decode(46, input).unwrap().service, NtService::LockFile);
        assert_eq!(decode(47, input).unwrap().service, NtService::UnlockFile);
        assert_eq!(decode(48, input).unwrap().service, NtService::DuplicateObject);
        assert_eq!(decode(49, input).unwrap().service, NtService::CreateTimer);
        assert_eq!(decode(50, input).unwrap().service, NtService::SetTimer);
        assert_eq!(decode(51, input).unwrap().service, NtService::CancelTimer);
        assert_eq!(decode(59, input).unwrap().service, NtService::RtlInitUnicodeString);
        assert_eq!(decode(60, input).unwrap().service, NtService::RtlInitUnicodeStringEx);
        assert_eq!(decode(61, input).unwrap().service, NtService::QueryObject);
        assert_eq!(decode(62, input).unwrap().service, NtService::RtlInitAnsiString);
        assert_eq!(decode(63, input).unwrap().service, NtService::RtlInitAnsiStringEx);
        assert_eq!(decode(64, input).unwrap().service, NtService::QuerySecurityObject);
        assert_eq!(decode(65, input).unwrap().service, NtService::RtlQueryPerformanceCounter);
        assert_eq!(decode(66, input).unwrap().service, NtService::RtlQueryPerformanceFrequency);
        assert_eq!(decode(67, input).unwrap().service, NtService::RenameKey);
        assert_eq!(decode(68, input).unwrap().service, NtService::SetSecurityObject);
        assert_eq!(decode(69, input).unwrap().service, NtService::RtlAddAccessAllowedAce);
        assert_eq!(decode(70, input).unwrap().service, NtService::RtlAddAccessAllowedAceEx);
        assert_eq!(decode(71, input).unwrap().service, NtService::RtlAddAccessDeniedAce);
        assert_eq!(decode(72, input).unwrap().service, NtService::RtlAddAccessDeniedAceEx);
        assert_eq!(decode(73, input).unwrap().service, NtService::RtlAddAce);
        assert_eq!(decode(74, input).unwrap().service, NtService::RtlAddAuditAccessAce);
        assert_eq!(decode(75, input).unwrap().service, NtService::RtlAddAuditAccessAceEx);
        assert_eq!(decode(76, input).unwrap().service, NtService::RtlCreateAcl);
        assert_eq!(decode(77, input).unwrap().service, NtService::RtlCreateSecurityDescriptor);
        assert_eq!(decode(78, input).unwrap().service, NtService::RtlCreateUnicodeStringFromAsciiz);
        assert_eq!(decode(79, input).unwrap().service, NtService::RtlDosPathNameToNtPathNameU);
        assert_eq!(decode(80, input).unwrap().service, NtService::RtlFreeUnicodeString);
        assert_eq!(decode(81, input).unwrap().service, NtService::RtlGetAce);
        assert_eq!(decode(82, input).unwrap().service, NtService::RtlGetControlSecurityDescriptor);
        assert_eq!(decode(83, input).unwrap().service, NtService::RtlIsTextUnicode);
        assert_eq!(decode(84, input).unwrap().service, NtService::RtlLengthSecurityDescriptor);
        assert_eq!(decode(85, input).unwrap().service, NtService::RtlMakeSelfRelativeSD);
        assert_eq!(decode(86, input).unwrap().service, NtService::RtlNtStatusToDosError);
        assert_eq!(decode(87, input).unwrap().service, NtService::RtlQueryInformationAcl);
        assert_eq!(decode(88, input).unwrap().service, NtService::RtlSelfRelativeToAbsoluteSD);
        assert_eq!(decode(91, input).unwrap().service, NtService::RtlEnterCriticalSection);
        assert_eq!(decode(92, input).unwrap().service, NtService::RtlLeaveCriticalSection);
        assert_eq!(decode(93, input).unwrap().service, NtService::Vsnprintf);
        assert_eq!(decode(94, input).unwrap().service, NtService::RtlSizeHeap);
        assert_eq!(decode(95, input).unwrap().service, NtService::RtlExitUserThread);
        assert_eq!(decode(96, input).unwrap().service, NtService::RtlQueryUnbiasedInterruptTime);
        assert_eq!(decode(97, input).unwrap().service, NtService::DbgUiGetThreadDebugObject);
        assert_eq!(decode(98, input).unwrap().service, NtService::DbgUiIssueRemoteBreakin);
        assert_eq!(decode(229, input).unwrap().service, NtService::DbgUiConnectToDbg);
        assert_eq!(decode(230, input).unwrap().service, NtService::DbgUiContinue);
        assert_eq!(decode(231, input).unwrap().service, NtService::DbgUiRemoteBreakin);
        assert_eq!(decode(232, input).unwrap().service, NtService::DbgUiStopDebugging);
        assert_eq!(decode(233, input).unwrap().service, NtService::DbgUiWaitStateChange);
        assert_eq!(decode(234, input).unwrap().service, NtService::DbgUiConvertStateChangeStructure);
        assert_eq!(decode(235, input).unwrap().service, NtService::DbgUiDebugActiveProcess);
        assert_eq!(decode(236, input).unwrap().service, NtService::LdrAccessResource);
        assert_eq!(decode(237, input).unwrap().service, NtService::LdrAddDllDirectory);
        assert_eq!(decode(238, input).unwrap().service, NtService::LdrRemoveDllDirectory);
        assert_eq!(decode(239, input).unwrap().service, NtService::LdrAddRefDll);
        assert_eq!(decode(244, input).unwrap().service, NtService::LdrGetDllPath);
        assert_eq!(decode(245, input).unwrap().service, NtService::LdrSetDefaultDllDirectories);
        assert_eq!(decode(246, input).unwrap().service, NtService::LdrUnloadDll);
        assert_eq!(decode(247, input).unwrap().service, NtService::NtAccessCheck);
        assert_eq!(decode(248, input).unwrap().service, NtService::NtAdjustGroupsToken);
        assert_eq!(decode(249, input).unwrap().service, NtService::NtAdjustPrivilegesToken);
        assert_eq!(decode(250, input).unwrap().service, NtService::NtAllocateLocallyUniqueId);
        assert_eq!(decode(251, input).unwrap().service, NtService::NtAllocateVirtualMemoryEx);
        assert_eq!(decode(252, input).unwrap().service, NtService::NtCancelIoFile);
        assert_eq!(decode(253, input).unwrap().service, NtService::NtCancelIoFileEx);
        assert_eq!(decode(254, input).unwrap().service, NtService::NtCancelSynchronousIoFile);
        assert_eq!(decode(255, input).unwrap().service, NtService::NtCompareObjects);
        assert_eq!(decode(256, input).unwrap().service, NtService::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter);
        assert_eq!(decode(257, input).unwrap().service, NtService::NtCreateNamedPipeFile);
        assert_eq!(decode(258, input).unwrap().service, NtService::NtCreateSectionEx);
        assert_eq!(decode(259, input).unwrap().service, NtService::NtCreateSymbolicLinkObject);
        assert_eq!(decode(260, input).unwrap().service, NtService::NtCreateUserProcess);
        assert_eq!(decode(261, input).unwrap().service, NtService::NtDelayExecution);
        assert_eq!(decode(262, input).unwrap().service, NtService::NtDeleteKey);
        assert_eq!(decode(263, input).unwrap().service, NtService::NtDeleteValueKey);
        assert_eq!(decode(264, input).unwrap().service, NtService::NtDuplicateToken);
        assert_eq!(decode(265, input).unwrap().service, NtService::NtEnumerateKey);
        assert_eq!(decode(266, input).unwrap().service, NtService::NtEnumerateValueKey);
        assert_eq!(decode(267, input).unwrap().service, NtService::NtFilterToken);
        assert_eq!(decode(268, input).unwrap().service, NtService::NtFlushBuffersFile);
        assert_eq!(decode(269, input).unwrap().service, NtService::NtFlushInstructionCache);
        assert_eq!(decode(270, input).unwrap().service, NtService::NtFlushKey);
    assert_eq!(decode(271, input).unwrap().service, NtService::NtFlushVirtualMemory);
    assert_eq!(decode(272, input).unwrap().service, NtService::NtGetContextThread);
    assert_eq!(decode(274, input).unwrap().service, NtService::NtGetTickCount);
    assert_eq!(decode(275, input).unwrap().service, NtService::NtGetWriteWatch);
    assert_eq!(decode(276, input).unwrap().service, NtService::NtImpersonateAnonymousToken);
    assert_eq!(decode(277, input).unwrap().service, NtService::NtIsProcessInJob);
    assert_eq!(decode(278, input).unwrap().service, NtService::NtLoadKey);
    assert_eq!(decode(279, input).unwrap().service, NtService::NtLockVirtualMemory);
    assert_eq!(decode(280, input).unwrap().service, NtService::NtMakeTemporaryObject);
    assert_eq!(decode(281, input).unwrap().service, NtService::NtMapViewOfSectionEx);
    assert_eq!(decode(282, input).unwrap().service, NtService::NtNotifyChangeDirectoryFile);
    assert_eq!(decode(283, input).unwrap().service, NtService::NtNotifyChangeKey);
    assert_eq!(decode(284, input).unwrap().service, NtService::NtOpenEvent);
    assert_eq!(decode(286, input).unwrap().service, NtService::NtOpenMutant);
    assert_eq!(decode(287, input).unwrap().service, NtService::NtOpenProcess);
    assert_eq!(decode(288, input).unwrap().service, NtService::NtOpenSection);
    assert_eq!(decode(289, input).unwrap().service, NtService::NtOpenSemaphore);
    assert_eq!(decode(290, input).unwrap().service, NtService::NtOpenSymbolicLinkObject);
    assert_eq!(decode(291, input).unwrap().service, NtService::NtOpenThread);
    assert_eq!(decode(292, input).unwrap().service, NtService::NtOpenTimer);
    assert_eq!(decode(293, input).unwrap().service, NtService::NtPrivilegeCheck);
    assert_eq!(decode(294, input).unwrap().service, NtService::NtPulseEvent);
    assert_eq!(decode(295, input).unwrap().service, NtService::NtQueryAttributesFile);
    assert_eq!(decode(296, input).unwrap().service, NtService::NtQueryDefaultLocale);
    assert_eq!(decode(297, input).unwrap().service, NtService::NtQueryDefaultUILanguage);
    assert_eq!(decode(300, input).unwrap().service, NtService::NtQueryInstallUILanguage);
    assert_eq!(decode(301, input).unwrap().service, NtService::NtQueryKey);
    assert_eq!(decode(302, input).unwrap().service, NtService::NtQueryPerformanceCounter);
    assert_eq!(decode(303, input).unwrap().service, NtService::NtQuerySymbolicLinkObject);
    assert_eq!(decode(304, input).unwrap().service, NtService::NtQuerySystemInformationEx);
    assert_eq!(decode(305, input).unwrap().service, NtService::NtQueryValueKey);
    assert_eq!(decode(306, input).unwrap().service, NtService::NtQueryVolumeInformationFile);
    assert_eq!(decode(307, input).unwrap().service, NtService::NtQueueApcThread);
    assert_eq!(decode(308, input).unwrap().service, NtService::NtQueueApcThreadEx2);
    assert_eq!(decode(309, input).unwrap().service, NtService::NtRaiseException);
    assert_eq!(decode(310, input).unwrap().service, NtService::NtReadFileScatter);
    assert_eq!(decode(311, input).unwrap().service, NtService::NtReadVirtualMemory);
    assert_eq!(decode(312, input).unwrap().service, NtService::NtRemoveIoCompletionEx);
    assert_eq!(decode(313, input).unwrap().service, NtService::NtResetWriteWatch);
    assert_eq!(decode(314, input).unwrap().service, NtService::NtResumeThread);
    assert_eq!(decode(315, input).unwrap().service, NtService::NtSaveKey);
    assert_eq!(decode(316, input).unwrap().service, NtService::NtSetContextThread);
    assert_eq!(decode(317, input).unwrap().service, NtService::NtSetInformationObject);
    assert_eq!(decode(318, input).unwrap().service, NtService::NtSetInformationToken);
    assert_eq!(decode(319, input).unwrap().service, NtService::NtSetInformationVirtualMemory);
    assert_eq!(decode(320, input).unwrap().service, NtService::NtSetSystemInformation);
    assert_eq!(decode(321, input).unwrap().service, NtService::NtSetSystemTime);
    assert_eq!(decode(322, input).unwrap().service, NtService::NtSetValueKey);
    assert_eq!(decode(323, input).unwrap().service, NtService::NtSuspendThread);
    assert_eq!(decode(324, input).unwrap().service, NtService::NtUnloadKey);
    assert_eq!(decode(325, input).unwrap().service, NtService::NtUnlockVirtualMemory);
    assert_eq!(decode(326, input).unwrap().service, NtService::NtUnmapViewOfSectionEx);
    assert_eq!(decode(327, input).unwrap().service, NtService::NtWriteFileGather);
    assert_eq!(decode(328, input).unwrap().service, NtService::NtWriteVirtualMemory);
    assert_eq!(decode(329, input).unwrap().service, NtService::NtYieldExecution);
    assert_eq!(decode(330, input).unwrap().service, NtService::RtlActivateActivationContext);
    assert_eq!(decode(331, input).unwrap().service, NtService::RtlActivateActivationContextEx);
    assert_eq!(decode(332, input).unwrap().service, NtService::RtlAddAccessAllowedObjectAce);
    assert_eq!(decode(333, input).unwrap().service, NtService::RtlAddAccessDeniedObjectAce);
    assert_eq!(decode(334, input).unwrap().service, NtService::RtlAddAuditAccessObjectAce);
    assert_eq!(decode(335, input).unwrap().service, NtService::RtlAddMandatoryAce);
    assert_eq!(decode(336, input).unwrap().service, NtService::RtlAddRefActivationContext);
    assert_eq!(decode(337, input).unwrap().service, NtService::RtlAllocateAndInitializeSid);
    assert_eq!(decode(338, input).unwrap().service, NtService::RtlAreAllAccessesGranted);
    assert_eq!(decode(339, input).unwrap().service, NtService::RtlAreAnyAccessesGranted);
    assert_eq!(decode(340, input).unwrap().service, NtService::RtlBarrier);
    assert_eq!(decode(341, input).unwrap().service, NtService::RtlClearBits);
    assert_eq!(decode(342, input).unwrap().service, NtService::RtlCompactHeap);
    assert_eq!(decode(343, input).unwrap().service, NtService::RtlCompareUnicodeStrings);
    assert_eq!(decode(344, input).unwrap().service, NtService::RtlConvertSidToUnicodeString);
    assert_eq!(decode(345, input).unwrap().service, NtService::RtlConvertToAutoInheritSecurityObject);
    assert_eq!(decode(346, input).unwrap().service, NtService::RtlCopyContext);
    assert_eq!(decode(347, input).unwrap().service, NtService::RtlCopySid);
    assert_eq!(decode(348, input).unwrap().service, NtService::RtlCreateActivationContext);
    assert_eq!(decode(349, input).unwrap().service, NtService::RtlCreateEnvironment);
    assert_eq!(decode(350, input).unwrap().service, NtService::RtlCreateProcessParametersEx);
    assert_eq!(decode(351, input).unwrap().service, NtService::RtlCreateTimer);
    assert_eq!(decode(352, input).unwrap().service, NtService::RtlCreateTimerQueue);
    assert_eq!(decode(353, input).unwrap().service, NtService::RtlCreateUserStack);
    assert_eq!(decode(354, input).unwrap().service, NtService::RtlDeactivateActivationContext);
    assert_eq!(decode(355, input).unwrap().service, NtService::RtlReleaseActivationContext);
    assert_eq!(decode(356, input).unwrap().service, NtService::RtlDeleteAce);
    assert_eq!(decode(357, input).unwrap().service, NtService::RtlDeleteBarrier);
    assert_eq!(decode(358, input).unwrap().service, NtService::RtlDeleteSecurityObject);
    assert_eq!(decode(359, input).unwrap().service, NtService::RtlDeleteTimer);
    assert_eq!(decode(360, input).unwrap().service, NtService::RtlDeleteTimerQueueEx);
    assert_eq!(decode(361, input).unwrap().service, NtService::RtlDeregisterWaitEx);
    assert_eq!(decode(362, input).unwrap().service, NtService::RtlDeriveCapabilitySidsFromName);
    assert_eq!(decode(363, input).unwrap().service, NtService::RtlDestroyEnvironment);
    assert_eq!(decode(364, input).unwrap().service, NtService::RtlDestroyProcessParameters);
    assert_eq!(decode(365, input).unwrap().service, NtService::RtlDoesFileExistsU);
    assert_eq!(decode(366, input).unwrap().service, NtService::RtlDosSearchPathU);
    assert_eq!(decode(367, input).unwrap().service, NtService::RtlDowncaseUnicodeChar);
    assert_eq!(decode(368, input).unwrap().service, NtService::RtlDuplicateUnicodeString);
    assert_eq!(decode(369, input).unwrap().service, NtService::RtlEqualPrefixSid);
    assert_eq!(decode(372, input).unwrap().service, NtService::RtlFindActivationContextSectionGuid);
    assert_eq!(decode(373, input).unwrap().service, NtService::RtlFindClearBitsAndSet);
    assert_eq!(decode(374, input).unwrap().service, NtService::RtlFindMessage);
    assert_eq!(decode(375, input).unwrap().service, NtService::RtlFirstFreeAce);
    assert_eq!(decode(376, input).unwrap().service, NtService::RtlFlsAlloc);
    assert_eq!(decode(377, input).unwrap().service, NtService::RtlFlsFree);
    assert_eq!(decode(378, input).unwrap().service, NtService::RtlFlsGetValue);
    assert_eq!(decode(379, input).unwrap().service, NtService::RtlFlsSetValue);
    assert_eq!(decode(380, input).unwrap().service, NtService::RtlFormatMessage);
    assert_eq!(decode(381, input).unwrap().service, NtService::RtlFormatMessageEx);
    assert_eq!(decode(382, input).unwrap().service, NtService::RtlFreeThreadActivationContextStack);
    assert_eq!(decode(383, input).unwrap().service, NtService::RtlFreeActivationContextStack);
    assert_eq!(decode(384, input).unwrap().service, NtService::RtlFreeAnsiString);
    assert_eq!(decode(385, input).unwrap().service, NtService::RtlFreeSid);
    assert_eq!(decode(386, input).unwrap().service, NtService::RtlFreeUserStack);
    assert_eq!(decode(387, input).unwrap().service, NtService::RtlGetActiveActivationContext);
    assert_eq!(decode(388, input).unwrap().service, NtService::RtlGetCurrentDirectoryU);
    assert_eq!(decode(389, input).unwrap().service, NtService::RtlGetCurrentPeb);
    assert_eq!(decode(390, input).unwrap().service, NtService::RtlGetDaclSecurityDescriptor);
    assert_eq!(decode(391, input).unwrap().service, NtService::RtlGetEnabledExtendedFeatures);
    assert_eq!(decode(392, input).unwrap().service, NtService::RtlGetExePath);
    assert_eq!(decode(393, input).unwrap().service, NtService::RtlGetExtendedContextLength2);
    assert_eq!(decode(394, input).unwrap().service, NtService::RtlGetExtendedFeaturesMask);
    assert_eq!(decode(395, input).unwrap().service, NtService::RtlGetFullPathNameU);
    assert_eq!(decode(396, input).unwrap().service, NtService::RtlGetGroupSecurityDescriptor);
    assert_eq!(decode(397, input).unwrap().service, NtService::RtlGetLocaleFileMappingAddress);
    assert_eq!(decode(398, input).unwrap().service, NtService::RtlGetNativeSystemInformation);
    assert_eq!(decode(399, input).unwrap().service, NtService::RtlGetOwnerSecurityDescriptor);
    assert_eq!(decode(400, input).unwrap().service, NtService::RtlGetProductInfo);
    assert_eq!(decode(401, input).unwrap().service, NtService::RtlGetProcessPreferredUILanguages);
    assert_eq!(decode(402, input).unwrap().service, NtService::RtlGetSaclSecurityDescriptor);
    assert_eq!(decode(403, input).unwrap().service, NtService::RtlGetSearchPath);
    assert_eq!(decode(404, input).unwrap().service, NtService::RtlGetSystemPreferredUILanguages);
    assert_eq!(decode(405, input).unwrap().service, NtService::RtlGetSystemTimePrecise);
    assert_eq!(decode(406, input).unwrap().service, NtService::RtlGetThreadErrorMode);
    assert_eq!(decode(407, input).unwrap().service, NtService::RtlGetThreadPreferredUILanguages);
    assert_eq!(decode(408, input).unwrap().service, NtService::RtlGetUserPreferredUILanguages);
    assert_eq!(decode(409, input).unwrap().service, NtService::RtlGetVersion);
    assert_eq!(decode(410, input).unwrap().service, NtService::RtlIdentifierAuthoritySid);
    assert_eq!(decode(411, input).unwrap().service, NtService::RtlIdnToAscii);
    assert_eq!(decode(412, input).unwrap().service, NtService::RtlIdnToNameprepUnicode);
    assert_eq!(decode(413, input).unwrap().service, NtService::RtlIdnToUnicode);
    assert_eq!(decode(414, input).unwrap().service, NtService::RtlImpersonateSelf);
    assert_eq!(decode(415, input).unwrap().service, NtService::RtlInitBarrier);
    assert_eq!(decode(416, input).unwrap().service, NtService::RtlInitCodePageTable);
    assert_eq!(decode(370, input).unwrap().service, NtService::RtlEqualSid);
    assert_eq!(decode(371, input).unwrap().service, NtService::RtlExpandEnvironmentStringsU);
    assert_eq!(decode(298, input).unwrap().service, NtService::NtQueryDirectoryObject);
    assert_eq!(decode(299, input).unwrap().service, NtService::NtQueryFullAttributesFile);
    assert_eq!(decode(293, input).unwrap().service, NtService::NtPrivilegeCheck);
        assert_eq!(decode(240, input).unwrap().service, NtService::LdrDisableThreadCalloutsForDll);
        assert_eq!(decode(99, input).unwrap().service, NtService::LdrGetDllDirectory);
        assert_eq!(decode(100, input).unwrap().service, NtService::LdrGetProcedureAddress);
        assert_eq!(decode(101, input).unwrap().service, NtService::LdrSetDllDirectory);
        assert_eq!(decode(102, input).unwrap().service, NtService::AddAtom);
        assert_eq!(decode(103, input).unwrap().service, NtService::AssignProcessToJobObject);
        assert_eq!(decode(104, input).unwrap().service, NtService::CreateJobObject);
        assert_eq!(decode(105, input).unwrap().service, NtService::CreateMailslotFile);
        assert_eq!(decode(106, input).unwrap().service, NtService::DeleteAtom);
        assert_eq!(decode(107, input).unwrap().service, NtService::DeviceIoControlFile);
        assert_eq!(decode(108, input).unwrap().service, NtService::FindAtom);
        assert_eq!(decode(109, input).unwrap().service, NtService::FsControlFile);
        assert_eq!(decode(110, input).unwrap().service, NtService::OpenJobObject);
        assert_eq!(decode(111, input).unwrap().service, NtService::PowerInformation);
        assert_eq!(decode(112, input).unwrap().service, NtService::QueryInformationAtom);
        assert_eq!(decode(113, input).unwrap().service, NtService::QueryInformationJobObject);
        assert_eq!(decode(114, input).unwrap().service, NtService::QuerySection);
        assert_eq!(decode(115, input).unwrap().service, NtService::QuerySystemInformation);
        assert_eq!(decode(116, input).unwrap().service, NtService::QuerySystemTime);
        assert_eq!(decode(117, input).unwrap().service, NtService::SetInformationDebugObject);
        assert_eq!(decode(118, input).unwrap().service, NtService::SetInformationJobObject);
        assert_eq!(decode(119, input).unwrap().service, NtService::SetInformationProcess);
        assert_eq!(decode(120, input).unwrap().service, NtService::SetInformationThread);
        assert_eq!(decode(121, input).unwrap().service, NtService::SetThreadExecutionState);
        assert_eq!(decode(122, input).unwrap().service, NtService::TerminateJobObject);
        assert_eq!(decode(123, input).unwrap().service, NtService::RtlAcquirePebLock);
        assert_eq!(decode(124, input).unwrap().service, NtService::RtlReleasePebLock);
        assert_eq!(decode(125, input).unwrap().service, NtService::RtlAddAtomToAtomTable);
        assert_eq!(decode(126, input).unwrap().service, NtService::RtlAnsiStringToUnicodeString);
        assert_eq!(decode(89, input).unwrap().service, NtService::RtlUniform);
        assert_eq!(decode(90, input).unwrap().service, NtService::RtlDeleteCriticalSection);
        assert_eq!(decode(154, input).unwrap().service, NtService::RtlGetLastWin32Error);
        assert_eq!(decode(155, input).unwrap().service, NtService::RtlRestoreLastWin32Error);
        assert_eq!(decode(160, input).unwrap().service, NtService::RtlTimeFieldsToTime);
        assert_eq!(decode(161, input).unwrap().service, NtService::RtlTimeToTimeFields);
        assert_eq!(decode(162, input).unwrap().service, NtService::RtlUnicodeStringToAnsiSize);
        assert_eq!(decode(163, input).unwrap().service, NtService::RtlUnicodeStringToAnsiString);
        assert_eq!(decode(164, input).unwrap().service, NtService::RtlUnicodeStringToInteger);
        assert_eq!(decode(165, input).unwrap().service, NtService::RtlUnicodeStringToOemSize);
        assert_eq!(decode(166, input).unwrap().service, NtService::RtlUnicodeStringToOemString);
        assert_eq!(decode(167, input).unwrap().service, NtService::RtlUnicodeToMultiByteN);
        assert_eq!(decode(168, input).unwrap().service, NtService::RtlUnicodeToMultiByteSize);
        assert_eq!(decode(169, input).unwrap().service, NtService::RtlUnicodeToOemN);
        assert_eq!(decode(170, input).unwrap().service, NtService::RtlUpcaseUnicodeString);
        assert_eq!(decode(171, input).unwrap().service, NtService::RtlUpperChar);
        assert_eq!(decode(172, input).unwrap().service, NtService::Wcsicmp);
        assert_eq!(decode(173, input).unwrap().service, NtService::Wcsnicmp);
        assert_eq!(decode(174, input).unwrap().service, NtService::Isalpha);
        assert_eq!(decode(175, input).unwrap().service, NtService::Islower);
        assert_eq!(decode(176, input).unwrap().service, NtService::Memcpy);
        assert_eq!(decode(177, input).unwrap().service, NtService::Memmove);
        assert_eq!(decode(178, input).unwrap().service, NtService::Memset);
        assert_eq!(decode(179, input).unwrap().service, NtService::Strcat);
        assert_eq!(decode(180, input).unwrap().service, NtService::Strchr);
        assert_eq!(decode(181, input).unwrap().service, NtService::Strcpy);
        assert_eq!(decode(182, input).unwrap().service, NtService::Strlen);
        assert_eq!(decode(183, input).unwrap().service, NtService::Strpbrk);
        assert_eq!(decode(184, input).unwrap().service, NtService::Strrchr);
        assert_eq!(decode(185, input).unwrap().service, NtService::Tolower);
        assert_eq!(decode(186, input).unwrap().service, NtService::Wcscat);
        assert_eq!(decode(187, input).unwrap().service, NtService::Wcschr);
        assert_eq!(decode(188, input).unwrap().service, NtService::Wcscmp);
        assert_eq!(decode(189, input).unwrap().service, NtService::Wcscpy);
        assert_eq!(decode(190, input).unwrap().service, NtService::Wcslen);
        assert_eq!(decode(191, input).unwrap().service, NtService::Wcsncmp);
        assert_eq!(decode(192, input).unwrap().service, NtService::Wcsrchr);
        assert_eq!(decode(193, input).unwrap().service, NtService::Wcstoul);
        assert_eq!(decode(194, input).unwrap().service, NtService::WineDbgHeader);
        assert_eq!(decode(195, input).unwrap().service, NtService::WineDbgOutput);
        assert_eq!(decode(196, input).unwrap().service, NtService::WineDbgStrdup);
        assert_eq!(decode(197, input).unwrap().service, NtService::RtlGUIDFromString);
        assert_eq!(decode(198, input).unwrap().service, NtService::RtlRandom);
        assert_eq!(decode(199, input).unwrap().service, NtService::WineGetHostVersion);
        assert_eq!(decode(200, input).unwrap().service, NtService::RtlInterlockedFlushSList);
        assert_eq!(decode(201, input).unwrap().service, NtService::RtlInterlockedPushEntrySList);
        assert_eq!(decode(202, input).unwrap().service, NtService::RtlTryEnterCriticalSection);
        assert_eq!(decode(203, input).unwrap().service, NtService::RtlAreBitsClear);
        assert_eq!(decode(204, input).unwrap().service, NtService::RtlAreBitsSet);
        assert_eq!(decode(205, input).unwrap().service, NtService::RtlInitializeBitMap);
        assert_eq!(decode(206, input).unwrap().service, NtService::RtlLookupFunctionEntry);
        assert_eq!(decode(207, input).unwrap().service, NtService::RtlPcToFileHeader);
        assert_eq!(decode(208, input).unwrap().service, NtService::RtlSetBits);
        assert_eq!(decode(209, input).unwrap().service, NtService::RtlTimeToSecondsSince1970);
        assert_eq!(decode(210, input).unwrap().service, NtService::RtlUnwindEx);
        assert_eq!(decode(211, input).unwrap().service, NtService::Setjmp);
        assert_eq!(decode(212, input).unwrap().service, NtService::Setjmpex);
        assert_eq!(decode(213, input).unwrap().service, NtService::Longjmp);
        assert_eq!(decode(214, input).unwrap().service, NtService::WineDbgGetChannelFlags);
        assert_eq!(decode(215, input).unwrap().service, NtService::LdrGetDllFullName);
        assert_eq!(decode(216, input).unwrap().service, NtService::LdrLoadDll);
        assert_eq!(decode(217, input).unwrap().service, NtService::LdrQueryImageFileExecutionOptions);
        assert_eq!(decode(218, input).unwrap().service, NtService::CallbackReturn);
        assert_eq!(decode(219, input).unwrap().service, NtService::OpenDirectoryObject);
        assert_eq!(decode(220, input).unwrap().service, NtService::RtlFindActivationContextSectionString);
        assert_eq!(decode(221, input).unwrap().service, NtService::RtlImageDirectoryEntryToData);
        assert_eq!(decode(222, input).unwrap().service, NtService::RtlImageRvaToVa);
        assert_eq!(decode(223, input).unwrap().service, NtService::RtlInitializeNtUserPfn);
        assert_eq!(decode(224, input).unwrap().service, NtService::RtlMultiByteToUnicodeN);
        assert_eq!(decode(225, input).unwrap().service, NtService::RtlMultiByteToUnicodeSize);
        assert_eq!(decode(226, input).unwrap().service, NtService::RtlRetrieveNtUserPfn);
        assert_eq!(decode(227, input).unwrap().service, NtService::RtlResetNtUserPfn);
        assert_eq!(decode(228, input).unwrap().service, NtService::ApiSetQueryApiSetPresenceEx);
    }

    #[test]
    fn byte_range_lock_records_are_fixed_x64_shapes() {
        let input = SyscallArgs { a0: 0x1000, ..args() };
        assert_eq!(core::mem::size_of::<NtLockFileRequest>(), 32);
        assert_eq!(core::mem::align_of::<NtLockFileRequest>(), 8);
        assert_eq!(core::mem::size_of::<NtUnlockFileRequest>(), 32);
        assert_eq!(core::mem::align_of::<NtUnlockFileRequest>(), 8);
        assert_eq!(core::mem::size_of::<NtDuplicateObjectRequest>(), 48);
        assert!(matches!(decode_object(decode(48, input).unwrap()), Ok(NtObjectCall::DuplicateObject { .. })));
        assert!(matches!(decode_file(decode(46, input).unwrap()), Ok(NtFileCall::Lock { .. })));
        assert!(matches!(decode_file(decode(47, input).unwrap()), Ok(NtFileCall::Unlock { .. })));
    }

    #[test]
    fn job_object_services_preserve_x64_pointer_and_handle_arguments() {
        let input = SyscallArgs { a0: 0x4000, a1: 0x001f_001f, a2: 0x8000, a3: 0, a4: 0, a5: 0 };
        assert!(matches!(decode_object(decode(104, input).unwrap()), Ok(NtObjectCall::CreateJob { handle, desired_access: 0x001f_001f, attributes: 0x8000 }) if handle.as_u64() == 0x4000));
        assert_eq!(decode_object(decode(103, SyscallArgs { a0: 7, a1: u64::MAX, ..input }).unwrap()), Ok(NtObjectCall::AssignProcessToJobObject { job: 7, process: u64::MAX }));
    }

    #[test]
    fn heap_services_preserve_windows_argument_order() {
        let input = args();
        assert_eq!(decode_heap(decode(25, input).unwrap()), Ok(NtHeapCall::Allocate {
            heap: u64::MAX, flags: 0x1122_3344_5566_7788, size: 3,
        }));
        assert_eq!(decode_heap(decode(26, input).unwrap()), Ok(NtHeapCall::Free {
            heap: u64::MAX, flags: 0x1122_3344_5566_7788, base: 3,
        }));
    }

    #[test]
    fn window_services_validate_message_output_pointer_and_preserve_scalars() {
        let input = SyscallArgs { a0: 0x4000, a1: 9, a2: 0x1122, a3: 0x3344, a4: 1, a5: 0 };
        assert_eq!(decode_window(decode(29, input).unwrap()), Ok(NtWindowCall::Post {
            hwnd: 0x4000, message: 9, wparam: 0x1122, lparam: 0x3344,
        }));
        assert_eq!(decode_window(decode(30, input).unwrap()), Ok(NtWindowCall::Peek {
            message: UserPtr::new(0x4000).unwrap(), hwnd: 9, first: 0x1122, last: 0x3344, remove: 1,
        }));
        assert_eq!(decode_window(decode(30, SyscallArgs { a0: 3, ..input }).unwrap()), Err(Errno::Efault));
        assert_eq!(decode_window(decode(32, input).unwrap()), Ok(NtWindowCall::DefaultProc {
            hwnd: 0x4000, message: 9, wparam: 0x1122, lparam: 0x3344,
        }));
    }

    #[test]
    fn unknown_service_is_rejected_before_work_can_run() {
        assert_eq!(decode(u32::MAX, args()), None);
    }

    #[test]
    fn linux_numbers_cannot_accidentally_enter_the_nt_namespace() {
        assert_eq!(decode_entry(9, args()), None);
        assert_eq!(decode_entry(NT_SERVICE_NAMESPACE | 3, args()).unwrap().service, NtService::QueryVirtualMemory);
        assert_eq!(decode_entry(NT_SERVICE_NAMESPACE | 4, args()).unwrap().service, NtService::TerminateProcess);
    }

    #[test]
    fn service_encoder_round_trips_through_the_nt_namespace() {
        let args = args();
        for service in [NtService::AllocateVirtualMemory, NtService::Close, NtService::QueryDirectoryFile] {
            let call = decode_entry(service.entry(), args).unwrap();
            assert_eq!(call.service, service);
            assert_eq!(call.args, args);
        }
    }

    #[test]
    fn memory_decode_validates_all_pointer_registers_before_work() {
        let args = SyscallArgs { a0: u64::MAX, a1: 0x1000, a2: 0, a3: 0x2000, a4: 0x3000, a5: 4 };
        let call = decode(0, args).unwrap();
        assert!(matches!(decode_memory(call), Ok(NtMemoryCall::Allocate { .. })));
        let bad = decode(0, SyscallArgs { a1: 0x1004, ..args }).unwrap();
        assert_eq!(decode_memory(bad), Err(Errno::Efault));
    }

    #[test]
    fn each_memory_service_has_its_windows_pointer_shape() {
        let a = SyscallArgs { a0: u64::MAX, a1: 0x1000, a2: 0x2000, a3: 0x3000, a4: 0x4000, a5: 0x5000 };
        assert!(matches!(decode_memory(decode(1, a).unwrap()), Ok(NtMemoryCall::Free { .. })));
        assert!(matches!(decode_memory(decode(2, a).unwrap()), Ok(NtMemoryCall::Protect { .. })));
        assert!(matches!(decode_memory(decode(3, a).unwrap()), Ok(NtMemoryCall::Query { .. })));
    }

    #[test]
    fn termination_keeps_the_process_handle_and_exit_status_scalar() {
        let call = decode(4, args()).unwrap();
        assert_eq!(decode_terminate(call), Ok((u64::MAX, 0x5566_7788u32)));
        assert_eq!(decode_terminate(decode(0, args()).unwrap()), Err(Errno::Enosys));
    }

    #[test]
    fn object_decode_validates_create_pointer_and_preserves_handle_ops() {
        let create = decode(5, SyscallArgs { a0: 0x1000, a1: 0x1f0003, a2: 0, a3: 1, a4: 1, a5: 0 }).unwrap();
        assert!(matches!(decode_object(create), Ok(NtObjectCall::CreateEvent { event_type: 1, initial_state: 1, .. }))); assert!(matches!(decode_object(decode(36, SyscallArgs { a0: 0x1000, a1: 0x1f0003, a2: 0, a3: 2, a4: 4, a5: 0 }).unwrap()), Ok(NtObjectCall::CreateSemaphore { initial: 2, maximum: 4, .. })));
        let bad = decode(5, SyscallArgs { a0: 0x1002, ..create.args }).unwrap();
        assert_eq!(decode_object(bad), Err(Errno::Efault));
        assert_eq!(decode_object(decode(6, args()).unwrap()), Ok(NtObjectCall::Close { handle: u64::MAX as u32 }));
        let op_args = SyscallArgs { a0: u64::MAX, a1: 0, ..args() };
        assert_eq!(decode_object(decode(7, op_args).unwrap()), Ok(NtObjectCall::SetEvent { handle: u64::MAX as u32, previous: None }));
        assert_eq!(decode_object(decode(8, op_args).unwrap()), Ok(NtObjectCall::ResetEvent { handle: u64::MAX as u32, previous: None }));
        assert!(matches!(decode_object(decode(9, SyscallArgs { a0: 7, a1: 1, a2: 0, ..args() }).unwrap()), Ok(NtObjectCall::WaitEvent { handle: 7, alertable: 1, timeout: None })));
        assert!(matches!(decode_object(decode(17, SyscallArgs { a0: 2, a1: 0x1000, a2: 1, a3: 1, a4: 0, ..args() }).unwrap()), Ok(NtObjectCall::WaitMultiple { count: 2, wait_type: 1, alertable: 1, timeout: None, .. })));
        assert!(matches!(decode_object(decode(18, SyscallArgs { a0: 0x1000, a1: 4, a2: 0x2000, a3: 4, a4: 0, a5: 9 }).unwrap()), Ok(NtObjectCall::CreateSection { file: 9, .. })));
        assert!(matches!(decode_object(decode(21, SyscallArgs { a0: u64::MAX, a1: 0, a2: 0x1000, a3: 48, a4: 0, ..args() }).unwrap()), Ok(NtObjectCall::QueryProcess { class: 0, length: 48, .. })));
        assert!(matches!(decode_object(decode(22, SyscallArgs { a0: 0x1000, a1: u64::MAX, a2: 0x4000, a3: 7, a4: 0x1000, a5: 0 }).unwrap()), Ok(NtObjectCall::CreateThreadEx { start: 0x4000, parameter: 7, .. })));
        assert_eq!(decode_object(decode(23, SyscallArgs { a0: u64::MAX, a1: 9, ..args() }).unwrap()), Ok(NtObjectCall::TerminateThread { thread: u64::MAX, status: 9 }));
        assert!(matches!(decode_object(decode(24, SyscallArgs { a0: u64::MAX, a1: 0, a2: 0x1000, a3: 48, a4: 0, ..args() }).unwrap()), Ok(NtObjectCall::QueryThread { class: 0, length: 48, .. })));
        assert!(matches!(decode_object(decode(49, SyscallArgs { a0: 0x1000, a1: 0x1f0003, a2: 0, a3: 0, ..args() }).unwrap()), Ok(NtObjectCall::CreateTimer { timer_type: 0, .. })));
        assert!(matches!(decode_object(decode(50, SyscallArgs { a0: 7, a1: 0x1000, a2: 0, a3: 0, ..args() }).unwrap()), Ok(NtObjectCall::SetTimer { handle: 7, .. })));
        assert!(matches!(decode_object(decode(51, SyscallArgs { a0: 7, a1: 0x1000, ..args() }).unwrap()), Ok(NtObjectCall::CancelTimer { handle: 7, .. })));
        assert!(matches!(decode_object(decode(55, SyscallArgs { a0: 7, a1: 8, a2: 1, a3: 0, ..args() }).unwrap()), Ok(NtObjectCall::SignalAndWait { signal: 7, wait: 8, alertable: 1, timeout: None })));
        assert!(matches!(decode_object(decode(56, SyscallArgs { a0: u64::MAX, a1: 8, a2: 0x1000, ..args() }).unwrap()), Ok(NtObjectCall::OpenProcessToken { process: u64::MAX, desired_access: 8, .. })));
        assert!(matches!(decode_object(decode(57, SyscallArgs { a0: u64::MAX, a1: 8, a2: 1, a3: 0x1000, ..args() }).unwrap()), Ok(NtObjectCall::OpenThreadToken { thread: u64::MAX, desired_access: 8, open_as_self: 1, .. })));
        assert!(matches!(decode_object(decode(58, SyscallArgs { a0: 7, a1: 8, a2: 0x1000, a3: 8, a4: 0, ..args() }).unwrap()), Ok(NtObjectCall::QueryToken { token: 7, class: 8, length: 8, .. })));
    }

    #[test]
    fn timeout_encoding_preserves_relative_and_absolute_units() {
        assert_eq!(decode_timeout(0), Ok(NtTimeout::Relative100ns(0)));
        assert_eq!(decode_timeout(-25), Ok(NtTimeout::Relative100ns(25)));
        assert_eq!(decode_timeout(25), Ok(NtTimeout::Absolute100ns(25)));
        assert_eq!(decode_timeout(i64::MIN), Err(Errno::Einval));
    }

    #[test]
    fn file_services_validate_the_outer_request_pointer() {
        let call = decode(10, SyscallArgs { a0: 0x1000, ..args() }).unwrap();
        assert!(matches!(decode_file(call), Ok(NtFileCall::Create { .. })));
        let bad = decode(12, SyscallArgs { a0: 0x1004, ..args() }).unwrap();
        assert_eq!(decode_file(bad), Err(Errno::Efault));
        assert_eq!(decode_file(decode(9, args()).unwrap()), Err(Errno::Enosys));
    }

    #[test]
    fn file_request_records_keep_the_x64_wire_layout() {
        assert_eq!(core::mem::size_of::<NtCreateFileRequest>(), 48);
        assert_eq!(core::mem::size_of::<NtOpenFileRequest>(), 32);
        assert_eq!(core::mem::size_of::<NtFileIoRequest>(), 40);
        assert_eq!(core::mem::size_of::<NtFileInformationRequest>(), 32);
    }
