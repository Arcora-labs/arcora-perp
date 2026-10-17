// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ChainlinkNativeContractBridgeTypes as T} from "./ChainlinkNativeContractBridgeTypes.sol";

/// NEW target-bound PUBLIC synthetic native witness. Mock proof is opaque,
/// not SP1 proof evidence. Runtime identity is checked by the EVM harness.
library ChainlinkNativeContractBridgeVector {
    // Exact bridge.json SHA256: b9349a3a9aba7f71e6f87c5ac88e1134e443fc3c56c00e06e1a3dd03740b922b
    function normal() internal pure returns (T.VectorData memory d) {
        d.witnessSha256 = 0x24b4e42a71ea3c595bdb6b33ab5f76eb3bf8e2d1d78ca11b12f26951d46a2e8b;
        d.nativeCommitment = 0x0a3467646ab9a432388e8636bcdd3e33123960d1a36e9711723c71ee2cc0607e;
        d.context.chainId = 84532;
        d.context.network = 0;
        d.context.clockVerifier = address(bytes20(hex"a0cb889707d426a7a386870a03bc70d1b0697598"));
        d.context.settlement = address(bytes20(hex"1d1499e622d69689cdf9004d05ec547d650ff211"));
        d.context.oracleWrapper = address(bytes20(hex"c7183455a4c133ae270771860664b6b7ec320bb1"));
        d.context.verifierProxy = address(bytes20(hex"f62849f9a0b5bf2913b396098f7c7019b51a820a"));
        d.context.sp1Adapter = address(bytes20(hex"2e234dae75c793f67a35089c9d99245e1c58470b"));
        d.context.sp1Gateway = address(bytes20(hex"5615deb798bb3e4dfa0139dfa1b3d433cc23b72f"));
        d.context.uptimeFeed = address(bytes20(hex"5991a2df15a8f6a256d3ec51e99254cd3fb576a9"));
        d.context.prefixVault = address(bytes20(hex"a4ad4f68d0b91cfd19687c881e50f3a00242828c"));
        d.context.clockVerifierCodeHash = 0xa924816dfe21cd5a9ce2b33f1a371416db138a23a49f16e89ace18d745db2884;
        d.context.settlementCodeHash = 0x23541913601cec70f1413a33e8e3e6c318c8aa9d99d9ee94bbd985cbbc276b96;
        d.context.oracleWrapperCodeHash = 0x3717502c4a11c244aa51c4b7ae204552cb49812a2f7e62dd656279baabb71496;
        d.context.verifierProxyCodeHash = 0x5a47fb9cac2982bdd2a985378e6441745c462fbffc033e146c41dd6331da02a6;
        d.context.sp1AdapterCodeHash = 0xd56f4ddc2f56975a65f76bea2d73ef9ef919367b2971ebeb7ee72da271f8b20b;
        d.context.sp1GatewayCodeHash = 0x06a648dd559448677178eb5d73ddd2384a1edf2be24cfb3d2cc641c98d69d5b1;
        d.context.uptimeFeedCodeHash = 0x82d11ffaf65eeef4186281bda26b1ed1bd2530f275f4f8d92b41602329fba162;
        d.context.prefixVaultCodeHash = 0xfc7dd7c9bd033c03d382e7cd40c65c2a93f4bab2db6a362a45948144106a6cc8;
        d.context.anchoredAtMs = 2001000;
        d.context.maxWindowMs = 10000;
        d.context.clockSkewMs = 2000;
        d.context.uptimeRoundId = 0x0102030405060708090a;
        d.context.uptimeStartedAt = 1000;
        d.context.graceSeconds = 60;
        d.context.registeredReceipt = 0xee21feabe44c2c90926113b386c729e478a70ff41bed0919d526014f9197286f;
        d.context.clockCommitment = 0x81333aa435a05202ded54c0e8efd0e924490ef32296e2aeb81f1a8fa0d7a9c21;
        d.context.sourceWitnessSha256 = 0x8f23160f0a0ff9d004c4c78a25877fc84f4e50e8263b46115695f1d212f9e937;
        d.context.baseCommitment = 0x256171682dea83b3e27550a45be485205aef4367a4c6edf996ca7c6a408ebded;
        d.context.policyHash = 0x838e511e4830062b4c478f7a0147acd4816e7be666f420951714a5b588f3fb1e;
        d.context.postConsumedDepositCount = 9;
        d.context.postConsumedDepositTip = 0x37a168caed4266e25f5c0d4959b86a6247c66dd25eb409fd782aed04b917bd4d;
        d.context.programVkey = 0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590;
    }

    function liquidation() internal pure returns (T.VectorData memory d) {
        d.witnessSha256 = 0x3bc9cacd53408bfab5ad7c5efadde48fd7ad357c3189479bb9f4564c31781086;
        d.nativeCommitment = 0xc6a41be0a278ffcb101d7c030ee5dc6cbc33651042e2c1b409ab6a3c715d337b;
        d.context.chainId = 84532;
        d.context.network = 0;
        d.context.clockVerifier = address(bytes20(hex"a0cb889707d426a7a386870a03bc70d1b0697598"));
        d.context.settlement = address(bytes20(hex"1d1499e622d69689cdf9004d05ec547d650ff211"));
        d.context.oracleWrapper = address(bytes20(hex"c7183455a4c133ae270771860664b6b7ec320bb1"));
        d.context.verifierProxy = address(bytes20(hex"f62849f9a0b5bf2913b396098f7c7019b51a820a"));
        d.context.sp1Adapter = address(bytes20(hex"2e234dae75c793f67a35089c9d99245e1c58470b"));
        d.context.sp1Gateway = address(bytes20(hex"5615deb798bb3e4dfa0139dfa1b3d433cc23b72f"));
        d.context.uptimeFeed = address(bytes20(hex"5991a2df15a8f6a256d3ec51e99254cd3fb576a9"));
        d.context.prefixVault = address(bytes20(hex"a4ad4f68d0b91cfd19687c881e50f3a00242828c"));
        d.context.clockVerifierCodeHash = 0xa924816dfe21cd5a9ce2b33f1a371416db138a23a49f16e89ace18d745db2884;
        d.context.settlementCodeHash = 0x23541913601cec70f1413a33e8e3e6c318c8aa9d99d9ee94bbd985cbbc276b96;
        d.context.oracleWrapperCodeHash = 0x3717502c4a11c244aa51c4b7ae204552cb49812a2f7e62dd656279baabb71496;
        d.context.verifierProxyCodeHash = 0x5a47fb9cac2982bdd2a985378e6441745c462fbffc033e146c41dd6331da02a6;
        d.context.sp1AdapterCodeHash = 0xd56f4ddc2f56975a65f76bea2d73ef9ef919367b2971ebeb7ee72da271f8b20b;
        d.context.sp1GatewayCodeHash = 0x06a648dd559448677178eb5d73ddd2384a1edf2be24cfb3d2cc641c98d69d5b1;
        d.context.uptimeFeedCodeHash = 0x82d11ffaf65eeef4186281bda26b1ed1bd2530f275f4f8d92b41602329fba162;
        d.context.prefixVaultCodeHash = 0x03a910435e6fe21599fe38b99c7bd4129d004312e6e3fb4060a2873b1d30ccfc;
        d.context.anchoredAtMs = 2001000;
        d.context.maxWindowMs = 10000;
        d.context.clockSkewMs = 2000;
        d.context.uptimeRoundId = 0x0102030405060708090a;
        d.context.uptimeStartedAt = 1000;
        d.context.graceSeconds = 60;
        d.context.registeredReceipt = 0x8bfeafc830724d950d41cf42485a9e729f5871ee5b29d8132c14e2381834e1a8;
        d.context.clockCommitment = 0xc5e49fb55c41b53b2fe093d417911669ac907bf2653195223274734a5a5ffa5a;
        d.context.sourceWitnessSha256 = 0xba6b4cd72a38db1c4b0188b9eff98e41022dffceca7dd5de5ff47b0f5adb0337;
        d.context.baseCommitment = 0xf7dc2d83e3dab565df22bbf976ac97db52ac010f23bec475d92315b0c63054c8;
        d.context.policyHash = 0x838e511e4830062b4c478f7a0147acd4816e7be666f420951714a5b588f3fb1e;
        d.context.postConsumedDepositCount = 9;
        d.context.postConsumedDepositTip = 0xc636f302abf2cd534baa683356c6543b356ea81b8fc62b5188edb58b22693458;
        d.context.programVkey = 0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590;
    }
}
