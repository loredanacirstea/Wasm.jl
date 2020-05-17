using Wasm
using Test

mem = Wasm.Memory(1)
#wasm1 = String(take!(f))
# print(wasm1)
#wasm = Vector{UInt8}(wasm1)
#wasm = Array{UInt8, 1}(wasm1)
wasm1 = open(f->read(f, String), "test/add.wasm")
wasm = Vector{UInt8}(wasm1)
print("\nfile size: ",length(wasm),"\n")
#print(wasm, import_value, import_function, mem)
m = Wasm.Mod(wasm, Wasm.import_value, Wasm.import_function, mem)
#print(m.)
#dump(m)
#print(m)
Wasm.init(m)
Wasm.dump(m)
#print(m.export_list)

print("\n-----------------------_________-------------------\n")

@testset "Wasm.jl" begin
    # Write your own tests here.
    @test Wasm.run(m, "add", [3,5])  == 0
end
