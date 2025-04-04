// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

contract LumiToken is ERC20, Ownable {
    mapping(uint256 => bool) public usedNonces;

    event Mint(address indexed to, uint256 value);

    constructor() ERC20("LumiToken", "LTK") Ownable(msg.sender) {}

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
        emit Mint(to, amount);
    }

    function mintWithSignature(address to, uint256 amount, uint256 nonce, bytes memory signature) external {
        require(!usedNonces[nonce], "Nonce already used");

        // Hash the transaction data to create a unique message
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));

        // Create the Ethereum signed message hash
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // Recover the signer address from the signature
        address signer = recoverSigner(ethSignedMessageHash, signature);

        require(signer == owner(), "Invalid signature");

        usedNonces[nonce] = true;

        _mint(to, amount);
        emit Mint(to, amount);
    }

    // Helper function to recover the signer address from a signature
    function recoverSigner(bytes32 ethSignedMessageHash, bytes memory signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    // Function to split the signature into its components (v, r, s)
    function splitSignature(bytes memory signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(signature.length == 65, "invalid signature length");

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
    }
    // Helper function to create a valid mint signature (to be signed off-chain by the owner)

    function createMintSignature(address to, uint256 amount, uint256 nonce) external view returns (bytes32) {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));

        // Return the hashed message with Ethereum prefix for signing
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }
}
