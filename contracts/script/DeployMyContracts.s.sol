// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {IAllocationManager} from "eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IBN254CertificateVerifier} from
    "@eigenlayer-contracts/src/contracts/interfaces/IBN254CertificateVerifier.sol";
import {ITaskMailbox} from "@hourglass-monorepo/src/interfaces/core/ITaskMailbox.sol";

import {TaskAVSRegistrar} from "@project/l1-contracts/TaskAVSRegistrar.sol";
import {AVSTaskHook} from "@project/l2-contracts/AVSTaskHook.sol";
import {ContractAudit} from "@project/ContractAudit.sol";

contract DeployMyContracts is Script {
    using stdJson for string;

    struct Context {
        address avs;
        uint256 avsPrivateKey;
        uint256 deployerPrivateKey;
        IAllocationManager allocationManager;
        IKeyRegistrar keyRegistrar;
        IBN254CertificateVerifier certificateVerifier;
        ITaskMailbox taskMailbox;
        TaskAVSRegistrar taskAVSRegistrar;
        AVSTaskHook taskHook;
    }

    struct Output {
        string name;
        address contractAddress;
    }

    uint32 constant EXECUTOR_OPERATOR_SET_ID = 1;
    
    function run(string memory environment, string memory _context) public {
        Context memory context = _readContext(environment, _context);

        vm.startBroadcast(context.deployerPrivateKey);

        ContractAudit contractAudit = new ContractAudit(
            address(context.taskMailbox),
            context.avs,
            EXECUTOR_OPERATOR_SET_ID
        );
        console.log("ContractAudit deployed:", address(contractAudit));

        vm.stopBroadcast();

        vm.startBroadcast(context.avsPrivateKey);

        if (!contractAudit.hasRole(contractAudit.ADMIN_ROLE(), context.avs)) {
            contractAudit.grantRole(contractAudit.ADMIN_ROLE(), context.avs);
        }
        
        if (!contractAudit.hasRole(contractAudit.FEE_COLLECTOR_ROLE(), context.avs)) {
            contractAudit.grantRole(contractAudit.FEE_COLLECTOR_ROLE(), context.avs);
        }

        _registerInitialOperators(environment, contractAudit);

        vm.stopBroadcast();

        Output[] memory outputs = new Output[](1);
        outputs[0] = Output({name: "ContractAudit", contractAddress: address(contractAudit)});
        _writeOutputToJson(environment, outputs);
    }

    function _registerInitialOperators(string memory environment, ContractAudit contractAudit) internal {
        string memory operatorsConfigFile = string.concat("script/", environment, "/operators.json");
        
        try vm.readFile(operatorsConfigFile) returns (string memory operatorsConfig) {
            address[] memory operators = stdJson.readAddressArray(operatorsConfig, ".operators");
            
            for (uint256 i = 0; i < operators.length; i++) {
                if (!contractAudit.isOperatorRegistered(operators[i])) {
                    contractAudit.registerOperator(operators[i]);
                }
            }
        } catch Error(string memory) {
            // Operators file not found - skip registration
        }
    }

    function _readContext(
        string memory environment,
        string memory _context
    ) internal view returns (Context memory) {
        Context memory context;
        context.avs = stdJson.readAddress(_context, ".context.avs.address");
        context.avsPrivateKey = uint256(stdJson.readBytes32(_context, ".context.avs.avs_private_key"));
        context.deployerPrivateKey = uint256(stdJson.readBytes32(_context, ".context.deployer_private_key"));
        context.allocationManager = IAllocationManager(stdJson.readAddress(_context, ".context.eigenlayer.l1.allocation_manager"));
        context.keyRegistrar = IKeyRegistrar(stdJson.readAddress(_context, ".context.eigenlayer.l1.key_registrar"));
        context.certificateVerifier = IBN254CertificateVerifier(stdJson.readAddress(_context, ".context.eigenlayer.l2.bn254_certificate_verifier"));
        context.taskMailbox = ITaskMailbox(_readHourglassConfigAddress(environment, "taskMailbox"));
        context.taskAVSRegistrar = TaskAVSRegistrar(_readAVSL1ConfigAddress(environment, "taskAVSRegistrar"));
        context.taskHook = AVSTaskHook(_readAVSL2ConfigAddress(environment, "avsTaskHook"));

        return context;
    }

    function _readHourglassConfigAddress(
        string memory environment,
        string memory key
    ) internal view returns (address) {
        // Load the Hourglass config file
        string memory hourglassConfigFile =
                            string.concat("script/", environment, "/output/deploy_hourglass_core_output.json");
        string memory hourglassConfig = vm.readFile(hourglassConfigFile);

        return stdJson.readAddress(hourglassConfig, string.concat(".addresses.", key));
    }

    function _readAVSL1ConfigAddress(string memory environment, string memory key) internal view returns (address) {
        string memory avsL1ConfigFile = string.concat("script/", environment, "/output/deploy_avs_l1_output.json");
        string memory avsL1Config = vm.readFile(avsL1ConfigFile);

        return stdJson.readAddress(avsL1Config, string.concat(".addresses.", key));
    }

    function _readAVSL2ConfigAddress(string memory environment, string memory key) internal view returns (address) {
        string memory avsL2ConfigFile = string.concat("script/", environment, "/output/deploy_avs_l2_output.json");
        string memory avsL2Config = vm.readFile(avsL2ConfigFile);

        return stdJson.readAddress(avsL2Config, string.concat(".addresses.", key));
    }

    function _writeOutputToJson(
        string memory environment,
        Output[] memory outputs
    ) internal {
        uint256 length = outputs.length;

        if (length > 0) {
            string memory addresses = "addresses";

            for (uint256 i = 0; i < outputs.length - 1; i++) {
                vm.serializeAddress(addresses, outputs[i].name, outputs[i].contractAddress);
            }
            addresses = vm.serializeAddress(addresses, outputs[length - 1].name, outputs[length - 1].contractAddress);

            string memory chainInfo = "chainInfo";
            chainInfo = vm.serializeUint(chainInfo, "chainId", block.chainid);

            string memory auditInfo = "auditInfo";
            auditInfo = vm.serializeUint(auditInfo, "executorOperatorSetId", EXECUTOR_OPERATOR_SET_ID);
            auditInfo = vm.serializeString(auditInfo, "minAuditFee", "0.01 ether");

            string memory finalJson = "final";
            vm.serializeString(finalJson, "addresses", addresses);
            vm.serializeString(finalJson, "chainInfo", chainInfo);
            finalJson = vm.serializeString(finalJson, "auditInfo", auditInfo);

            // Write to output file
            string memory outputFile = string.concat("script/", environment, "/output/deploy_contract_audit_output.json");
            vm.writeJson(finalJson, outputFile);
            
            console.log("\nDeployment output written to:", outputFile);
        }
    }
}

