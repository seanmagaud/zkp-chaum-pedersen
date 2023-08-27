# Zero-Knowledge Proof Authentication System

This project implements a zero-knowledge proof authentication system using the Chaum-Pedersen protocol. 

It allows users to register, authenticate, and verify their identity without revealing their actual credentials.

![pedersen](https://github.com/seanmagaud/zkp-chaum-pedersen/assets/90192506/98ad1f7e-337b-47d7-be15-218dcf096932)


## Prerequisites

Before you start, make sure you have the following dependency installed:

- Rust (tested with version 1.72.0)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/seanmagaud/zkp-chaum-pedersen
cd zkp-chaum-pedersen
```

2. Build the project:

```bash
cargo build
```

## Usage

1. Start the authentication server:

```bash
cargo run --bin server
```

2. Run the client to interact with the server:

```bash
cargo run --bin client
```

## How It Works

This zero-knowledge proof authentication system uses the Chaum-Pedersen protocol to achieve secure and private authentication. It involves the following steps:

1. **Registration**: Users register their credentials by providing their username and a password. The server computes the necessary parameters and stores the user's information.

2. **Authentication Challenge**: When a user wants to authenticate, the server sends a challenge to the user. The challenge includes random values and other parameters.

3. **Solution Submission**: The user calculates a solution based on the challenge and their password. They submit this solution to the server.

4. **Verification**: The server verifies the solution provided by the user using the stored user information and the computed challenge. If the verification is successful, the user is authenticated.

## Customization

You can customize various aspects of the authentication system by modifying the code in the respective files. For example, you can change cryptographic parameters, tweak the random number generation, and more.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to create a pull request or an issue on the GitHub repository.

## License

This project is licensed under the XYZ License - see the [LICENSE](./LICENSE) file for details.
