using Documenter, Wasm

makedocs(;
    modules=[Wasm],
    format=Documenter.HTML(),
    pages=[
        "Home" => "index.md",
    ],
    repo="https://github.com/ctzurcanu/Wasm.jl/blob/{commit}{path}#L{line}",
    sitename="Wasm.jl",
    authors="Loredana Cirstea, Christian Tzurcanu",
    assets=String[],
)

deploydocs(;
    repo="github.com/ctzurcanu/Wasm.jl",
)
