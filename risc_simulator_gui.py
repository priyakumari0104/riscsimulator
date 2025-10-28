import tkinter as tk
import time
import threading

# ---------------- CPU COMPONENTS ---------------- #
registers = {"R0": 0, "R1": 0, "R2": 0, "R3": 0, "PC": 0, "IR": "", "FLAGS": "Z=0 C=0 N=0 V=0"}
memory = [0] * 64
program = []
halted = False

# ---------------- SCROLLABLE ROOT WINDOW ---------------- #
root = tk.Tk()
root.title("RISC Simulator - Visual Edition")
root.geometry("900x600")

main_canvas = tk.Canvas(root, bg="#f0f4f7")
main_scroll = tk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
scrollable_frame = tk.Frame(main_canvas, bg="#f0f4f7")

scrollable_frame.bind("<Configure>", lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all")))
main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
main_canvas.configure(yscrollcommand=main_scroll.set)

main_canvas.pack(side="left", fill="both", expand=True)
main_scroll.pack(side="right", fill="y")

# ---------------- GUI SETUP ---------------- #
tk.Label(scrollable_frame, text="Registers", font=("Arial", 14, "bold"), bg="#f0f4f7").pack(pady=5)
reg_frame = tk.Frame(scrollable_frame, bg="#f0f4f7")
reg_frame.pack()
reg_labels = {}
for i, r in enumerate(registers):
    tk.Label(reg_frame, text=f"{r}:", font=("Consolas", 12, "bold"), width=6, bg="#f0f4f7").grid(row=i, column=0, sticky="e")
    reg_labels[r] = tk.Label(reg_frame, text=str(registers[r]), font=("Consolas", 12), width=20, bg="white", relief="solid")
    reg_labels[r].grid(row=i, column=1, padx=5, pady=2)

# --- Memory Display --- #
tk.Label(scrollable_frame, text="Memory", font=("Arial", 14, "bold"), bg="#f0f4f7").pack(pady=5)
mem_frame = tk.Frame(scrollable_frame, bg="#f0f4f7")
mem_frame.pack()
mem_canvas = tk.Canvas(mem_frame, width=400, height=150, bg="#ffffff")
mem_scroll = tk.Scrollbar(mem_frame, orient="vertical", command=mem_canvas.yview)
mem_inner = tk.Frame(mem_canvas, bg="#ffffff")
mem_inner.bind("<Configure>", lambda e: mem_canvas.configure(scrollregion=mem_canvas.bbox("all")))
mem_canvas.create_window((0, 0), window=mem_inner, anchor="nw")
mem_canvas.configure(yscrollcommand=mem_scroll.set)
mem_canvas.pack(side="left", fill="both", expand=True)
mem_scroll.pack(side="right", fill="y")

mem_labels = []
for i in range(len(memory)):
    lbl = tk.Label(mem_inner, text=f"[{i:02}] = {memory[i]}", font=("Consolas", 11), width=20, bg="white", relief="solid")
    lbl.grid(row=i, column=0, padx=4, pady=2)
    mem_labels.append(lbl)

# --- Stage + Output --- #
stage_label = tk.Label(scrollable_frame, text="Stage: READY", font=("Arial", 13, "italic"), bg="#f0f4f7")
stage_label.pack(pady=5)

tk.Label(scrollable_frame, text="Output:", font=("Arial", 13, "bold"), bg="#f0f4f7").pack()
output_box = tk.Text(scrollable_frame, height=4, width=80, font=("Consolas", 11), bg="#e8ffe8", relief="solid")
output_box.pack(pady=5)

# --- Assembly Input --- #
tk.Label(scrollable_frame, text="Assembly Code Input", font=("Arial", 14, "bold"), bg="#f0f4f7").pack(pady=5)
asm_text = tk.Text(scrollable_frame, height=10, width=80, font=("Consolas", 11), bg="#fff8e8")
asm_text.pack(pady=5)
asm_text.insert("1.0", "INP R0\nINP R1\nADD R2, R0, R1\nSUB R3, R2, R0\nOUT R2\nHLT")

# ---------------- CORE FUNCTIONS ---------------- #
def update_gui():
    for r in registers:
        reg_labels[r].config(text=str(registers[r]))
    for i in range(len(memory)):
        mem_labels[i].config(text=f"[{i:02}] = {memory[i]}")
    root.update()
    time.sleep(0.3)

def highlight_line(index):
    asm_text.tag_remove("highlight", "1.0", "end")
    asm_text.tag_add("highlight", f"{index + 1}.0", f"{index + 1}.end")
    asm_text.tag_config("highlight", background="yellow")

def set_flags(result):
    Z = 1 if result == 0 else 0
    N = 1 if result < 0 else 0
    C = 1 if result > 255 else 0
    V = 0
    registers["FLAGS"] = f"Z={Z} C={C} N={N} V={V}"

def fetch():
    if registers["PC"] < len(program):
        instr = program[registers["PC"]]
        registers["IR"] = instr
        stage_label.config(text=f"Stage: FETCH ({instr})")
        highlight_line(registers["PC"])
        update_gui()
        return instr
    else:
        return "HLT"

def decode(instr):
    stage_label.config(text="Stage: DECODE")
    update_gui()
    parts = instr.split()
    op = parts[0]
    args = [x.replace(",", "") for x in parts[1:]]
    return op, args

def execute(op, args):
    global halted
    stage_label.config(text="Stage: EXECUTE")
    update_gui()

    if op == "INP":
        reg = args[0]
        val = simple_input_popup(f"Enter value for {reg}:")
        registers[reg] = val
        memory[registers["PC"]] = val

    elif op == "ADD":
        rd, r1, r2 = args
        result = registers[r1] + registers[r2]
        set_flags(result)
        registers[rd] = result & 0xFF

    elif op == "SUB":
        rd, r1, r2 = args
        result = registers[r1] - registers[r2]
        set_flags(result)
        registers[rd] = result & 0xFF

    elif op == "OUT":
        reg = args[0]
        output_box.insert(tk.END, f"{registers[reg]}\n")
        output_box.see(tk.END)

    elif op == "HLT":
        halted = True
        stage_label.config(text="Stage: HALTED")

    registers["PC"] += 1
    update_gui()

def simple_input_popup(prompt):
    popup = tk.Toplevel(root)
    popup.title("Input")
    tk.Label(popup, text=prompt, font=("Arial", 12)).pack(padx=10, pady=10)
    val = tk.StringVar()
    entry = tk.Entry(popup, textvariable=val)
    entry.pack(padx=10, pady=5)
    entry.focus()
    tk.Button(popup, text="OK", command=popup.destroy).pack(pady=5)
    popup.grab_set()
    popup.wait_window()
    try:
        return int(val.get())
    except:
        return 0

def assemble_program():
    global program, halted
    halted = False
    registers["PC"] = 0
    output_box.delete("1.0", tk.END)
    lines = asm_text.get("1.0", tk.END).strip().splitlines()
    program = [line.strip().upper() for line in lines if line.strip()]
    stage_label.config(text="Program Assembled")
    highlight_line(0)
    update_gui()

def run_program():
    global halted
    halted = False
    while not halted:
        instr = fetch()
        op, args = decode(instr)
        execute(op, args)

def step_program():
    global halted
    if not halted:
        instr = fetch()
        op, args = decode(instr)
        execute(op, args)

# ---------------- BUTTONS (ALWAYS VISIBLE) ---------------- #
btn_frame = tk.Frame(scrollable_frame, bg="#f0f4f7")
btn_frame.pack(pady=15)
tk.Button(btn_frame, text="Assemble", command=assemble_program,
          bg="#cbe1ff", font=("Arial", 12, "bold"), width=10).grid(row=0, column=0, padx=10)
tk.Button(btn_frame, text="Run All", command=lambda: threading.Thread(target=run_program).start(),
          bg="#d4f8d4", font=("Arial", 12, "bold"), width=10).grid(row=0, column=1, padx=10)
tk.Button(btn_frame, text="Step", command=step_program,
          bg="#fef5d4", font=("Arial", 12, "bold"), width=10).grid(row=0, column=2, padx=10)

root.mainloop()
