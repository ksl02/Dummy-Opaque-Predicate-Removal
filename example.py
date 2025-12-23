import argparse
from io import BufferedReader,FileIO
from capstone import *

PREFIX = "[LOG] "

def log(str_:str):
    print(PREFIX+str_)

def op_str_ends_with_imm_lt(op_str:str,less_than:int):
    for i in range(less_than):
        if op_str.endswith(f"#{i}"):
            return True
    return False

class Function(BufferedReader):
    def __init__(self,fno:FileIO):
        super().__init__(fno)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.skipdata = True
        self.md.detail = True

        self.instructions = []
        self.instr_overflow = []

    def decode(self):
        complete = False
        while True:
            for instruction in self.md.disasm(self.read(32), self.addr):
                if complete:
                    self.instr_overflow.append(instruction)
                    continue
                if self.is_function_exit(instruction):
                    self.store(instruction)
                    complete = True
                    continue
                self.store(instruction)
                self.addr += 4
            if complete:
                log("Function information successfully stored. Patching can begin.")
                return

    def store(self,instruction):
        self.instructions.append(instruction)

    def get_instructions(self):
        return self.instructions

    def get_instr_overflow(self):
        return self.instr_overflow

    def is_function_exit(self,instruction):
        if self.end_address != None:
            if instruction.address+4 >= self.end_address:
                log(f"Hit specified function end address: {hex(instruction.address)}")
                return True
            return False
        
        mnemonic = instruction.mnemonic
        op_str = instruction.op_str

        #NOTE: Assuming instrunction that follows pattern below is end of function. This is not necessarily the case as some labels may be below these instructions. 
        #TODO: fix 
        #for now ignore add/mov/sub instructions referencing PC as rd due to some common obfuscation techniques.
        #this method may result in some false positives as it is possible these instructions will appear before the function end
        if mnemonic.startswith("pop") or (mnemonic.startswith("b") and op_str.startswith("lr")) or (mnemonic.startswith("ldr") and op_str.startswith("pc")):
            log(f"Found possible address of function end: {hex(instruction.address)}")
            return True
        return False

class Patcher(Function):
    def __init__(self,fno:FileIO,outputFn:str,funcAddr:int,endAddr:int=None):
        super().__init__(fno)
        self.end_address = endAddr
        self.addr = funcAddr
        self.output = open(outputFn,"wb+")
        self.output.write(self.read(self.addr))
        self.decode()

    def patch(self):
        patch_cnt = 0
        instructions = self.get_instructions()
        log(f"Begin patching function of size {len(instructions)*4} bytes.")
        for i,instr in enumerate(instructions):
            if i == 0 or i == len(instructions)-1:
                self.output.write(instr.bytes)
                continue

            prev_instr = instructions[i-1]
            next_instr = instructions[i+1]

            #It is likely that some false positives will be found as this detection only looks at 3 instructions to determine if pattern matches 
            if not self.curr_instr_met_criteria(instr) or not self.prev_instr_met_criteria(prev_instr) or not self.next_instr_met_criteria(next_instr):
                self.output.write(instr.bytes)
                continue

            log(f"Patched instruction at {hex(instr.address)}: {instr.mnemonic} {instr.op_str}")
            self.output.write(b"\x00\xf0 \xe3") #NOP
            patch_cnt += 1
        for instr in self.get_instr_overflow():
            self.output.write(instr.bytes)
        self.output.write(self.read())
        self.output.close()
        log(f"Completed patch! Modified {patch_cnt} instructions.")

    def curr_instr_met_criteria(self,instr):
        return instr.mnemonic.startswith("b") and not (instr.mnemonic.endswith("x") or instr.mnemonic == "bl" or instr.mnemonic == "b")

    def prev_instr_met_criteria(self,prev_instr):
        mn = prev_instr.mnemonic
        os = prev_instr.op_str
        return mn == "sbcs" or mn == "orrs" or (mn == "str" and (os.startswith("r"))) or (mn == "cmp" and op_str_ends_with_imm_lt(os,4))

    def next_instr_met_criteria(self,next_instr):
        return next_instr.mnemonic == "b"

def main(args):
    f = open(args.input_file,"rb")
    patcher = Patcher(FileIO(f.fileno()),args.output_file,args.start_addr,args.end_address)
    patcher.patch()
    f.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog = "remove_dummy_opaque_predicates.py", description = "Proof of concept removal of custom bogus control flow methods for obfuscation.")
    parser.add_argument("input_file",help="Input File Name",type=str)
    parser.add_argument("output_file",help="Output File Name",type=str)
    parser.add_argument("start_addr",help="Function Start Address",type= lambda x: int(x,0))
    parser.add_argument("-e","--end_address",help="Function End Address",type= lambda x: int(x,0),required=False)
    args = parser.parse_args()
    main(args)