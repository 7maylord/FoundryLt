// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/ERC20SIG.sol";

contract ERC20SIGTest is Test {

    LumiToken token;
    address owner = address(0x123);
    address user = address(0x456);
    address attacker = address(0x789);
    uint256 privateKeyOwner = 0x123456;
    uint256 privateKeyAttacker = 0x789101;

    function setUp() public {
        vm.prank(owner);
        token = new LumiToken();
    }

    function testMintWithSignature_ValidSigner() public {
        uint256 amount = 1000 * 10**18;
        uint256 nonce = 1;
        
        bytes32 messageHash = keccak256(abi.encodePacked(user, amount, nonce, address(token)));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeyOwner, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        token.mintWithSignature(user, amount, nonce, signature);
        
        assertEq(token.balanceOf(user), amount, "Minting with valid signature failed");
    }

    function testMintWithSignature_InvalidSigner() public {
        uint256 amount = 1000 * 10**18;
        uint256 nonce = 1;
        
        bytes32 messageHash = keccak256(abi.encodePacked(user, amount, nonce, address(token)));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeyAttacker, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert("Invalid signature");
        token.mintWithSignature(user, amount, nonce, signature);
    }
}
