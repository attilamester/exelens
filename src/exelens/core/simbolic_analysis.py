"""
angr analysis
"""
import os
import angr
from malflow import CallGraph
from malflow.core.model.function import CGNode



def angr_analysis(cg: CallGraph, node_to_reach: CGNode) -> str:
    """
    Performs symbolic analysis to find a path to the specified node using angr.
    
    :param cg: The CallGraph object containing binary metadata
    :param node_to_reach: The target CGNode to reach
    :return: A string description of how to reach the node or if it's unreachable
    """
    
    # 1. Locate the binary
    if not os.path.exists(cg.file_path):
        return f"Error: Binary for MD5 {cg.md5} not found at {cg.file_path}"

    try:
        # Silence some of the noisy loggers
        import logging
        logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel(logging.ERROR)
        logging.getLogger('cle.loader').setLevel(logging.ERROR)

        # 2. Load the binary
        # auto_load_libs=False to speed up loading and focus on the main binary
        proj = angr.Project(cg.file_path, auto_load_libs=False)
        
        # 3. Calculate target address
        # node_to_reach.rva.value is likely the RVA. 
        # We need to add it to the image base loaded by angr.
        target_rva = node_to_reach.rva.value
        if isinstance(target_rva, str):
            if target_rva.startswith("0x"):
                target_rva = int(target_rva, 16)
            else:
                target_rva = int(target_rva)
        
        # Check if RVA already includes the base address
        # The mapped base is usually 0x400000 (exe) or 0x10000000 (dll)
        # If RVA is large (e.g. > 0x400000), it might be an absolute address (VA) not RVA
        mapped_base = proj.loader.main_object.mapped_base
        
        if target_rva >= mapped_base:
             # It seems target_rva is actually a VA (Virtual Address)
             target_addr = target_rva
        else:
             target_addr = mapped_base + target_rva

        print(f"DEBUG: Mapped base: {hex(mapped_base)}")
        print(f"DEBUG: Target RVA (from node): {hex(target_rva)}")
        print(f"DEBUG: Target Address: {hex(target_addr)}")
        print(f"DEBUG: Entry point: {hex(proj.entry)}")

        # 4. Setup simulation
        # Start from the entry point
        # Add options to zero-fill unconstrained memory and registers to avoid warnings
        extras = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
        state = proj.factory.entry_state(add_options=extras)
        simgr = proj.factory.simulation_manager(state)

        # 5. Explore
        # Explore until we find a state at the target address
        # You might want to add 'n=' argument to explore to limit steps if needed
        print("DEBUG: Starting exploration...")
        simgr.explore(find=target_addr)
        print(f"DEBUG: Exploration finished. Found: {len(simgr.found)}, Errored: {len(simgr.errored)}, Active: {len(simgr.active)}, Deadended: {len(simgr.deadended)}")

        if simgr.deadended:
            last_state = simgr.deadended[0]
            print(f"DEBUG: Last address of deadended state: {hex(last_state.addr)}")
            try:
                # Try to see what instruction is at the last address or where we came from
                print(f"DEBUG: History (last 5 blocks): {[hex(x) for x in list(last_state.history.bbl_addrs)[-5:]]}")
            except:
                pass
            
            # Check if we are in a different object (DLL)
            try:
                obj = proj.loader.find_object_containing(last_state.addr)
                if obj:
                    print(f"DEBUG: Deadended in object: {obj.binary_basename} at base {hex(obj.mapped_base)}")
                else:
                    print("DEBUG: Deadended in unknown memory region")
                    
                # Inspect the instruction at the last block to see why it jumped there
                if last_state.history.bbl_addrs:
                    last_bbl_addr = list(last_state.history.bbl_addrs)[-1]
                    print(f"DEBUG: Last Basic Block: {hex(last_bbl_addr)}")
                    block = proj.factory.block(last_bbl_addr)
                    block.pp()
            except:
                pass

        if simgr.found:
            found_state = simgr.found[0]
            
            # Extract information about the path
            # This is a basic example. You might want to dump stdin, command line args, etc.
            result = "Path found!\n"
            
            # Example: Try to get stdin content if constrained
            stdin_content = found_state.posix.dumps(0)
            if stdin_content:
                result += f"Standard Input required: {stdin_content!r}\n"
            else:
                result += "No specific Standard Input constraints found.\n"
                
            # If we want to see basic blocks executed:
            # history = found_state.history.bbl_addrs
            # result += f"Basic blocks executed: {len(list(history))}\n"
            
            return result
            
        elif simgr.errored:
            return f"Analysis errored: {simgr.errored}"
            
        else:
            return "Path not found (exploration exhausted or timed out)."

    except Exception as e:
        return f"Angr analysis failed: {str(e)}"
