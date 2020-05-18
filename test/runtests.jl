#using Wasm
using Test


#print(m.export_list)
function setandrun(file, func, inputs, outputs)
    mem = Wasm.Memory(1)
    wasm1 = open(f->read(f, String), "test/" * file)
    wasm = Vector{UInt8}(wasm1)
    m = Wasm.Mod(wasm, Wasm.import_value, Wasm.import_function, mem)
    Wasm.init(m)
    #Wasm.dump(m)
    res = Wasm.run(m, func, inputs)
    print("\n---------------------+-----------------------\n")

    return res == outputs
end



@testset "Wasm.jl" begin
    # Write your own tests here.
    @test setandrun("add.wasm", "add", [3,5], 0)
    @test setandrun("call.wasm", "getAnswerPlus1", 0, 0)
    @test setandrun("sums.wasm", "sum_u8", [7,3], 0)
    @test setandrun("subs.wasm", "sub_u8", [7,73], 0)
    @test setandrun("wasm-table.wasm", "callByIndex", [2], 0)


end
