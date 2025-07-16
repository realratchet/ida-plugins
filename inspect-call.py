from typing import Generator, Literal
import idc
import idaapi
import ida_dbg
import ida_ida
import ida_funcs
import ida_ua
import ida_idp
import ida_kernwin
import idautils

ACTION_TRACE_FUNC = "dtrace:trace_func"
ACTION_TRACE_INSTR = "dtrace:trace_instr"
TOOLBAR_NAME = "Dynamic Analysis"

g_dynamic_tracer_plugin = None


class DbgHook(ida_dbg.DBG_Hooks):
    def update_ui(self):
        ida_kernwin.execute_sync(
            lambda: ida_kernwin.request_refresh(ida_kernwin.IWID_ALL),
            ida_kernwin.MFF_WRITE)

    def dbg_suspend_process(self, *args):
        self.update_ui()
        return 0

    def dbg_continue_process(self, *args):
        self.update_ui()
        return 0

    def dbg_process_exited(self, *args):
        """Called when the process exits."""
        self.update_ui()
        return 0


class ActionTraceFunctionHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        if g_dynamic_tracer_plugin:
            g_dynamic_tracer_plugin.trace_active_function()
        else:
            print("DynamicTracer Error: Plugin instance not found!")
        return 1

    def update(self, ctx):
        if g_dynamic_tracer_plugin and g_dynamic_tracer_plugin.is_tracing_active:
            return idaapi.AST_DISABLE_FOR_WIDGET
        if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class ActionTraceInstructionHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        if g_dynamic_tracer_plugin:
            g_dynamic_tracer_plugin.trace_instruction_under_cursor()
        else:
            print("DynamicTracer Error: Plugin instance not found!")
        return 1

    def update(self, ctx):
        if g_dynamic_tracer_plugin and g_dynamic_tracer_plugin.is_tracing_active:
            return idaapi.AST_DISABLE_FOR_WIDGET
        if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET


class DynamicTracerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Dynamically traces and resolves indirect calls within the debugger."
    help = "See source code for detailed instructions."
    wanted_name = "Dynamic Call Tracer"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.hotkey_ctx = None
        self.is_tracing_active = False
        self.dbg_hook = None

    def init(self):
        global g_dynamic_tracer_plugin
        g_dynamic_tracer_plugin = self

        self.dbg_hook = DbgHook()
        self.dbg_hook.hook()
        print("DynamicTracer: Debugger hook installed for responsive UI updates.")

        self.hotkey_ctx = ida_kernwin.add_hotkey("Ctrl-Alt-R", self.trace_instruction_under_cursor)
        if self.hotkey_ctx is None:
            ida_kernwin.warning("DynamicTracer: Failed to register hotkey Ctrl-Alt-R. It may be in use.")
        else:
            print("DynamicTracer: Hotkey 'Ctrl-Alt-R' for on-demand call resolving is active.")

        actions = [
            idaapi.action_desc_t(ACTION_TRACE_FUNC, "Trace active function", ActionTraceFunctionHandler(), None, "Trace all indirect calls in the current function", 20),
            idaapi.action_desc_t(ACTION_TRACE_INSTR, "Trace current instruction", ActionTraceInstructionHandler(), None, "Resolve indirect call under the cursor", 19)
        ]
        for action in actions:
            if not idaapi.register_action(action):
                print(f"DynamicTracer: Failed to register action '{action.name}'")

        if ida_kernwin.create_toolbar(TOOLBAR_NAME, "Dynamic Analysis"):
            ida_kernwin.attach_action_to_toolbar(TOOLBAR_NAME, ACTION_TRACE_FUNC)
            ida_kernwin.attach_action_to_toolbar(TOOLBAR_NAME, ACTION_TRACE_INSTR)
            print(f"DynamicTracer: Successfully created '{TOOLBAR_NAME}' toolbar.")
        else:
            print(f"DynamicTracer: Failed to create toolbar '{TOOLBAR_NAME}'")

        print("Dynamic Call Tracer plugin has been loaded.\n    > MAKE SURE 'Use hardware temporary breakpoints' is disabled")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.trace_active_function()

    def term(self):
        global g_dynamic_tracer_plugin

        if self.dbg_hook:
            self.dbg_hook.unhook()
            self.dbg_hook = None

        if self.hotkey_ctx:
            ida_kernwin.del_hotkey(self.hotkey_ctx)
        if ida_kernwin.delete_toolbar(TOOLBAR_NAME):
            print(f"DynamicTracer: Deleted toolbar '{TOOLBAR_NAME}'.")
        ida_kernwin.unregister_action(ACTION_TRACE_FUNC)
        ida_kernwin.unregister_action(ACTION_TRACE_INSTR)
        g_dynamic_tracer_plugin = None
        print("Dynamic Call Tracer plugin has been unloaded.")

    def is_64bit(self) -> bool:
        return ida_ida.inf_is_64bit()

    def get_reg_name(self) -> Literal["EIP", "RIP"]:
        return "RIP" if self.is_64bit() else "EIP"

    def get_active_func(self) -> ida_funcs.func_t | None:
        if not ida_dbg.is_debugger_on() or ida_dbg.get_process_state() != idc.DSTATE_SUSP:
            ida_kernwin.warning("DynamicTracer: Debugger must be active and suspended.")
            return None
        ip_reg_name = self.get_reg_name()
        start_ip = idc.get_reg_value(ip_reg_name)
        func = ida_funcs.get_func(start_ip)
        if not func:
            ida_kernwin.warning(f"DynamicTracer: Could not find a function at the current address 0x{start_ip:x}")
            return None
        return func

    def get_func_info(self, func: ida_funcs.func_t) -> tuple[str, int, int]:
        func_start_ea, func_end_ea = func.start_ea, func.end_ea
        func_name = idc.get_func_name(func_start_ea)
        return func_name, func_start_ea, func_end_ea

    def iter_func_instructions(self, func: ida_funcs.func_t) -> Generator[int, None, None]:
        ip_reg_name = self.get_reg_name()
        func_name, func_start_ea, func_end_ea = self.get_func_info(func)

        while True:
            if ida_kernwin.user_cancelled():
                print("DynamicTracer: Trace cancelled by user.")
                raise StopIteration

            current_ip = idc.get_reg_value(ip_reg_name)
            ida_kernwin.replace_wait_box(f"Tracing at 0x{current_ip:x}")

            if not (func_start_ea <= current_ip < func_end_ea):
                print(f"DynamicTracer: IP 0x{current_ip:x} is outside of '{func_name}'. Tracing finished.")
                raise StopIteration
            if ida_idp.is_ret_insn(current_ip):
                print(f"DynamicTracer: Found return instruction at 0x{current_ip:x}. Tracing finished.")
                raise StopIteration

            is_indirect_call = self.is_addr_call(current_ip)
            is_jmp = self.is_jump_insn(current_ip)

            if is_jmp or is_indirect_call:
                yield current_ip
                ida_dbg.step_over()
                ida_dbg.wait_for_next_event(idc.WFNE_SUSP, -1)
            else:
                next_target = self.find_next_interesting_instruction(current_ip, func_end_ea)
                if next_target != idc.BADADDR:
                    bpt = idaapi.bpt_t()
                    user_bpt_exists = ida_dbg.get_bpt(next_target, bpt)
                    original_bpt_props = None

                    if user_bpt_exists:
                        print(f"DynamicTracer: Found user BP at 0x{next_target:x}. Temporarily making it unconditional.")
                        original_bpt_props = {"condition": bpt.condition, "flags": bpt.flags, "pass_count": bpt.pass_count}
                        bpt.condition = ""
                        bpt.pass_count = 0
                        bpt.flags &= ~idc.BPT_BRK
                        ida_dbg.update_bpt(bpt)
                    else:
                        ida_dbg.add_bpt(next_target, 0, idc.BPT_SOFT)

                    ida_dbg.continue_process()
                    ida_dbg.wait_for_next_event(idc.WFNE_SUSP, -1)

                    if user_bpt_exists and original_bpt_props is not None:
                        print(f"DynamicTracer: Restoring user BP at 0x{next_target:x}.")
                        bpt.condition = original_bpt_props["condition"]
                        bpt.flags = original_bpt_props["flags"]
                        bpt.pass_count = original_bpt_props["pass_count"]
                        ida_dbg.update_bpt(bpt)
                    else:
                        ida_dbg.del_bpt(next_target)
                else:
                    ida_dbg.step_over()
                    ida_dbg.wait_for_next_event(idc.WFNE_SUSP, -1)

    def is_addr_call(self, current_ip: int) -> bool:
        if not ida_idp.is_call_insn(current_ip):
            return False
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, current_ip)
        target = idc.to_ea(insn.cs, insn.Op1.addr)
        name = idc.get_name(target, idc.GN_VISIBLE)
        return not name

    def iter_func_calls(self, func: ida_funcs.func_t) -> Generator[int, None, None]:
        for current_ip in self.iter_func_instructions(func):
            if not self.is_addr_call(current_ip):
                continue
            yield current_ip

    def follow_jmp_thunk(self, current_ip: int) -> int:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current_ip) > 0 and insn.get_canon_mnem() == 'jmp':
            jmp_dest = idc.get_operand_value(current_ip, 0)
            if jmp_dest != idc.BADADDR:
                print(f" -> Call landed on a JMP at 0x{current_ip:x}. Following to 0x{jmp_dest:x}")
                return jmp_dest
            else:
                print(f" -> Call landed on an unresolved JMP at 0x{current_ip:x}")
        return current_ip

    def get_indirect_function_name(self, func: ida_funcs.func_t, current_ip: int) -> str | None:
        ip_reg_name = self.get_reg_name()
        ida_dbg.step_into()
        ida_dbg.wait_for_next_event(idc.WFNE_SUSP, -1)
        target_ea = idc.get_reg_value(ip_reg_name)
        final_target_ea = self.follow_jmp_thunk(target_ea)
        next_ea_in_original_func = idc.next_head(current_ip, func.end_ea)

        if next_ea_in_original_func == idc.BADADDR:
            print("DynamicTracer: Error: Could not find instruction after call. Stopping trace.")
            raise IndexError

        print(f"DynamicTracer: Setting temp BP at 0x{next_ea_in_original_func:x} to resume trace.")
        ida_dbg.add_bpt(next_ea_in_original_func, 0, idc.BPT_SOFT)
        ida_dbg.continue_process()
        ida_dbg.wait_for_next_event(idc.WFNE_SUSP, -1)
        ida_dbg.del_bpt(next_ea_in_original_func)

        func_name = idc.get_func_name(final_target_ea)
        if not func_name:
            print(f"DynamicTracer: Resumed trace at 0x{idc.get_reg_value(ip_reg_name):x} but failed to resolve name")
            return None
        return func_name

    def trace_instruction(self, func: ida_funcs.func_t, current_ip: int) -> bool:
        existing_comment: str = idc.get_cmt(current_ip, 0)
        if existing_comment and "Resolved call: " in existing_comment:
            return False

        func_call_name = self.get_indirect_function_name(func, current_ip)
        if func_call_name is None:
            return False

        new_comment = f"Resolved call: {func_call_name}"
        if existing_comment:
            idc.set_cmt(current_ip, f"{existing_comment} | {new_comment}", 0)
        else:
            idc.set_cmt(current_ip, new_comment, 0)

        ida_kernwin.refresh_idaview_anyway()
        return True

    def trace_instruction_under_cursor(self) -> None:
        func = self.get_active_func()
        if not func:
            return
        ip_reg_name = self.get_reg_name()
        current_ip = idc.get_reg_value(ip_reg_name)
        if not self.is_addr_call(current_ip):
            return
        self.trace_instruction(func, current_ip)

    def trace_active_function(self) -> None:
        if self.is_tracing_active:
            print("DynamicTracer: A trace is already in progress.")
            return
        func = self.get_active_func()
        if func is None:
            return
        self.is_tracing_active = True
        ida_kernwin.show_wait_box("Tracing function... Click Cancel to stop.")
        try:
            print("--- DynamicTracer: Full Function Trace Started ---")
            commented_eas = set()
            for current_ip in self.iter_func_calls(func):
                if current_ip in commented_eas:
                    continue
                if not self.trace_instruction(func, current_ip):
                    continue
                commented_eas.add(current_ip)
        except (IndexError, StopIteration):
            pass  # Normal termination of the trace
        finally:
            print("--- DynamicTracer: Full Function Trace Finished ---")
            ida_kernwin.hide_wait_box()
            self.is_tracing_active = False

    def is_jump_insn(self, ea: int) -> bool:
        if ida_idp.is_call_insn(ea):
            return False

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) > 0:
            if insn.get_canon_feature() & ida_idp.CF_JUMP:
                return True

        for xref in idautils.XrefsFrom(ea, 0):
            if xref.type in [idc.fl_JN, idc.fl_JF]:
                return True

        return False

    def find_next_interesting_instruction(self, start_ea: int, end_ea: int) -> int:
        ea = idc.next_head(start_ea, end_ea)
        while ea != idc.BADADDR and ea < end_ea:
            if self.is_jump_insn(ea) or self.is_addr_call(ea):
                return ea
            ea = idc.next_head(ea, end_ea)
        return idc.BADADDR


def PLUGIN_ENTRY() -> DynamicTracerPlugin:
    return DynamicTracerPlugin()
