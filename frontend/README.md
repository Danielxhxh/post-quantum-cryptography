# ID Share SHOW Webapp

### Install Rust

Make sure to have installed `rust` in your machine before proceding.

## How to Install and Run the Project

1. Clone the repository locally using the git clone command:

```bash
git clone https://github.com/ErroFerro/id-share-show.git
```

2.  Inside the project folder, install all the dependencies:

```bash
npm i
```

3. Navigate inside the `src/ibe` folder and run these commands one by one:

```bash
#Compile local packages and all of their dependencies.
cargo build

#Download and install a tool named 'wasm-pack'.
cargo install wasm-pack

#Compile the code to WebAssembly
wasm-pack build --target web
```

4. To run the project run the command:

```bash
npm run dev
```

5. To build the project run the command:

```bash
npm run build
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)

# id-share-show
