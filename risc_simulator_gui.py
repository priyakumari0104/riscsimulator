import tkinter as tk
import time
import threading

# ---------------- CPU COMPONENTS ---------------- #
registers = {
    "A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "H": 0, "L": 0,
    "FLAGS": "Z=0 S=0 P=0 C=0 AC=0",
    "PC": 0,       # 16-bit Program Counter
    "SP": 1024,    # 16-bit Stack Pointer, set to the end of our 1KB RAM
    "IR": ""       # Instruction Register
}
# 1KB (1024 bytes) of memory
memory = [0] * 1024
clock_cycle=0
program = []
halted = False

# ---------------- SCROLLABLE ROOT WINDOW ---------------- #
root = tk.Tk()
root.title("RISC Simulator - Visual Edition")
root.geometry("1000x600")

main_canvas = tk.Canvas(root, bg="#f0f4f7")
main_scroll = tk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
scrollable_frame = tk.Frame(main_canvas, bg="#f0f4f7")

scrollable_frame.bind("<Configure>", lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all")))
main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
main_canvas.configure(yscrollcommand=main_scroll.set)

main_canvas.pack(side="left", fill="both", expand=True)
main_scroll.pack(side="right", fill="y")

# ---------------- MOUSEWHEEL SCROLLING ---------------- #
def _on_mousewheel(event):
    """Handles cross-platform mousewheel/touchpad scrolling."""
    # event.delta is for Windows/macOS (value is 120 or -120)
    # event.num is for Linux (value is 4 for up, 5 for down)
    
    delta = 0
    if hasattr(event, 'delta') and event.delta != 0:
        # Windows/macOS
        delta = int(-1 * (event.delta / 120))
    elif event.num == 4:
        # Linux scroll up
        delta = -1
    elif event.num == 5:
        # Linux scroll down
        delta = 1
    
    if delta != 0:
        main_canvas.yview_scroll(delta, "units")

def _on_mem_scroll(event):
    """Handles scrolling for the memory canvas."""
    delta = 0
    if hasattr(event, 'delta') and event.delta != 0:
        # Windows/macOS
        delta = int(-1 * (event.delta / 120))
    elif event.num == 4:
        # Linux scroll up
        delta = -1
    elif event.num == 5:
        # Linux scroll down
        delta = 1
    
    if delta != 0:
        mem_canvas.yview_scroll(delta, "units")
    
    return "break" # Stops the event from scrolling the main window

# Bind mousewheel events to the whole application
# This ensures scrolling works even if the mouse is over a child widget
root.bind_all("<MouseWheel>", _on_mousewheel) # For Windows/macOS
root.bind_all("<Button-4>", _on_mousewheel)   # For Linux (scroll up)
root.bind_all("<Button-5>", _on_mousewheel)   # For Linux (scroll down)

# ---------------- GUI LAYOUT (3-Column) ---------------- #
content_frame = tk.Frame(scrollable_frame, bg="#f0f4f7")
content_frame.pack(fill="both", expand=True, padx=20, pady=20)

# --- Column 1: Registers ---
col1_frame = tk.Frame(content_frame, bg="#f0f4f7")
col1_frame.pack(side="left", fill="y")

# --- Spacer 1 ---
spacer1 = tk.Frame(content_frame, width=20, bg="#f0f4f7")
spacer1.pack(side="left", fill="y")

# --- Column 2: Input/Output ---
col2_frame = tk.Frame(content_frame, bg="#f0f4f7")
col2_frame.pack(side="left", fill="y")

# --- Spacer 2 ---
spacer2 = tk.Frame(content_frame, width=20, bg="#f0f4f7")
spacer2.pack(side="left", fill="y")

# --- Column 3: Memory ---
col3_frame = tk.Frame(content_frame, bg="#f0f4f7")
col3_frame.pack(side="left", fill="y")

# --- Registers Display --- #
tk.Label(col1_frame, text="Registers", font=("Arial", 14, "bold"), bg="#f0f4f7").pack(pady=5)
reg_frame = tk.Frame(col1_frame, bg="#f0f4f7")
reg_frame.pack()
reg_labels = {}
for i, r in enumerate(registers):
    tk.Label(reg_frame, text=f"{r}:", font=("Consolas", 12, "bold"), width=6, bg="#f0f4f7").grid(row=i, column=0, sticky="e")
    reg_labels[r] = tk.Label(reg_frame, text=str(registers[r]), font=("Consolas", 12), width=20, bg="white", relief="solid")
    reg_labels[r].grid(row=i, column=1, padx=5, pady=2)

# -----------------------------Clock--------------------------------------
tk.Label(col1_frame, text="Clock Cycles:", font=("Arial", 13, "bold"), bg="#f0f4f7").pack(pady=(15, 0))
clock_label = tk.Label(col1_frame, text="0", font=("Consolas", 14, "bold"), bg="#e8f8ff", relief="solid", width=20)
clock_label.pack(pady=5)
# ---------------------------------------------------------------------------

# ---------------- HIGHLIGHT HELPERS ---------------- #
def highlight_instruction(line_no):
    asm_text.tag_remove("highlight", "1.0", "end")
    asm_text.tag_configure("highlight", background="#ff76e1")  # light yellow
    asm_text.tag_add("highlight", f"{line_no}.0", f"{line_no}.end")
    asm_text.see(f"{line_no}.0")

def highlight_memory(index):
    if 0 <= index < len(mem_labels):
        lbl = mem_labels[index]
        original = lbl.cget("bg")
        lbl.config(bg="#aeeeee")  # light cyan
        lbl.after(300, lambda: lbl.config(bg=original))

def goto_memory():
    """Scrolls the memory canvas to a specific address."""
    try:
        addr = int(mem_nav_entry.get())
        if 0 <= addr < len(memory):
            # Calculate the fractional position (0.0 to 1.0)
            position = addr / len(memory)
            mem_canvas.yview_moveto(position)
            highlight_memory(addr)
        else:
            output_box.insert(tk.END, f"Error: Address {addr} out of range.\n")
    except ValueError:
        output_box.insert(tk.END, "Error: Invalid address.\n")

# --- Memory Display --- #
tk.Label(col3_frame, text="Memory", font=("Arial", 14, "bold"), bg="#f0f4f7").pack(pady=(10, 5))
mem_frame = tk.Frame(col3_frame, bg="#f0f4f7")
mem_frame.pack()
mem_canvas = tk.Canvas(mem_frame, width=280, height=300, bg="#ffffff")
mem_scroll = tk.Scrollbar(mem_frame, orient="vertical", command=mem_canvas.yview)
mem_inner = tk.Frame(mem_canvas, bg="#ffffff")
mem_inner.bind("<Configure>", lambda e: mem_canvas.configure(scrollregion=mem_canvas.bbox("all")))
mem_canvas.create_window((0, 0), window=mem_inner, anchor="nw")
mem_canvas.configure(yscrollcommand=mem_scroll.set)
mem_canvas.pack(side="left", fill="both", expand=True)
mem_scroll.pack(side="right", fill="y")

# --- Memory Navigation Bar ---
nav_frame = tk.Frame(col3_frame, bg="#f0f4f7")
nav_frame.pack(pady=2)

# --- PREVIOUS BUTTON ---
tk.Button(nav_frame, text="Prev", font=("Arial", 9, "bold"), bg="#fef5d4", 
          command=lambda: mem_canvas.yview_scroll(-11, "units")).pack(side="left", padx=(0, 5))

# --- GOTO BOX ---
tk.Label(nav_frame, text="Go to:", font=("Arial", 10), bg="#f0f4f7").pack(side="left")
mem_nav_entry = tk.Entry(nav_frame, width=6, font=("Consolas", 11))
mem_nav_entry.pack(side="left", padx=(5, 5))
tk.Button(nav_frame, text="Go", font=("Arial", 9, "bold"), bg="#cbe1ff", command=goto_memory).pack(side="left")

# --- NEXT BUTTON ---
tk.Button(nav_frame, text="Next", font=("Arial", 9, "bold"), bg="#fef5d4", 
          command=lambda: mem_canvas.yview_scroll(11, "units")).pack(side="left", padx=(5, 0))

# --- Memory Key/Legend ---
key_frame = tk.Frame(col3_frame, bg="#f0f4f7")
key_frame.pack(pady=2)

# Key for Code
tk.Label(key_frame, text=" ", bg="#fff8e8", relief="solid", bd=1, width=2).pack(side="left", padx=(0, 2))
tk.Label(key_frame, text="Code (0-255)", font=("Arial", 9), bg="#f0f4f7").pack(side="left", padx=(0, 10))

# Key for Data
tk.Label(key_frame, text=" ", bg="#e8ffe8", relief="solid", bd=1, width=2).pack(side="left", padx=(0, 2))
tk.Label(key_frame, text="Data (256-767)", font=("Arial", 9), bg="#f0f4f7").pack(side="left", padx=(0, 10))

# Key for Stack
tk.Label(key_frame, text=" ", bg="#e8f8ff", relief="solid", bd=1, width=2).pack(side="left", padx=(0, 2))
tk.Label(key_frame, text="Stack (768-1023)", font=("Arial", 9), bg="#f0f4f7").pack(side="left")

# --- Bindings for Memory Scroll ---
mem_canvas.bind("<MouseWheel>", _on_mem_scroll)
mem_canvas.bind("<Button-4>", _on_mem_scroll)
mem_canvas.bind("<Button-5>", _on_mem_scroll)
mem_inner.bind("<MouseWheel>", _on_mem_scroll)
mem_inner.bind("<Button-4>", _on_mem_scroll)
mem_inner.bind("<Button-5>", _on_mem_scroll)

mem_labels = []
for i in range(len(memory)):
    color = "white" # Default
    if 0 <= i <= 255:
        color = "#fff8e8"  # Code section (light yellow)
    elif 256 <= i <= 767:
        color = "#e8ffe8"  # Data section (light green)
    elif 768 <= i <= 1023:
        color = "#e8f8ff"  # Stack section (light blue)
        
    lbl = tk.Label(mem_inner, text=f"[{i:02}] = {memory[i]}", font=("Consolas", 11), width=25, bg=color, relief="solid")
    lbl.grid(row=i, column=0, padx=4, pady=2)
    
    # Bind mousewheel events to the label
    lbl.bind("<MouseWheel>", _on_mem_scroll)
    lbl.bind("<Button-4>", _on_mem_scroll)
    lbl.bind("<Button-5>", _on_mem_scroll)
    
    mem_labels.append(lbl)

tk.Label(col2_frame, text="Assembly Code Input", font=("Arial", 14, "bold"), bg="#f0f4f7").pack(pady=5)
asm_text = tk.Text(col2_frame, height=12, width=40, font=("Consolas", 11), bg="#fff8e8")
asm_text.pack(pady=5)
asm_text.insert("1.0", """MVI A, 50
MVI B, 20
STA 300
ADD B
PUSH A
MVI A, 10
POP B
OUT B
HLT""")

# --- Stage ---
stage_label = tk.Label(col2_frame, text="Stage: READY", font=("Arial", 13, "italic"), bg="#f0f4f7")
stage_label.pack(pady=5)

# ---------------- CORE FUNCTIONS ---------------- #
def update_gui():
    for r in registers:
        reg_labels[r].config(text=str(registers[r]))
    for i in range(len(memory)):
        mem_labels[i].config(text=f"[{i:02}] = {memory[i]}")

    clock_label.config(text=str(clock_cycle))
    root.update()
    time.sleep(0.2)

def set_flags(result):
    Z = 1 if result == 0 else 0
    N = 1 if result < 0 else 0
    C = 1 if result > 255 else 0
    V = 0
    registers["FLAGS"] = f"Z={Z} C={C} N={N} V={V}"

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
    global halted, memory
    halted = False
    clock_cycle = 0
    registers["PC"] = 0
    output_box.delete("1.0", tk.END)
    
    # Reset memory
    memory = [0] * 1024 
    
    lines = asm_text.get("1.0", tk.END).strip().splitlines()
    addr = 0
    for line in lines:
        if line.strip():
            # Store the INSTRUCTION STRING directly into memory
            memory[addr] = line.strip().upper()
            addr += 1
            
    stage_label.config(text="Program Assembled")
    update_gui()

def fetch():
    if registers["PC"] < 1024:
        instr = memory[registers["PC"]]
        
        # Check for HLT or end of program
        if not instr or instr == "HLT":
             return "HLT"
             
        registers["IR"] = instr
        stage_label.config(text=f"Stage: FETCH ({instr})")
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
    global halted,clock_cycle
    stage_label.config(text="Stage: EXECUTE")
    update_gui()

    if op == "MVI":
        reg, val_str = args
        try:
            val = int(val_str)
            registers[reg] = val & 0xFF 
        except Exception as e:
            output_box.insert(tk.END, f"Error: {e}\n")
        clock_cycle += 7

    elif op == "STA":  # Store Accumulator (Data Constraint)
        # Usage: STA 500
        addr = int(args[0])
        # Optional: Add check for data area
        if 256 <= addr <= 767:
          memory[addr] = registers["A"]
          highlight_memory(addr)
        else:
            output_box.insert(tk.END, f"Error: STA accessing invalid memory {addr}\n")
        clock_cycle += 13

    elif op == "LDA":  # Load Accumulator (Data Constraint)
        # Usage: LDA 500
        addr = int(args[0])
        registers["A"] = memory[addr] & 0xFF
        highlight_memory(addr)
        clock_cycle += 13

    elif op == "PUSH":  # (Stack Constraint)
        # Usage: PUSH B
        reg = args[0]
        if reg in registers:
            registers["SP"] -= 1
            memory[registers["SP"]] = registers[reg]
            highlight_memory(registers["SP"])
        else:
            output_box.insert(tk.END, f"Error: Invalid register {reg}\n")
        clock_cycle += 11

    elif op == "POP":  
        reg = args[0]

        if reg in registers:

            # Stack Underflow (stack empty)
            if registers["SP"] >= 1024:
                output_box.insert(tk.END, "Error: Stack Underflow!\n")
                halted = True
            else:
                registers[reg] = memory[registers["SP"]] & 0xFF
                highlight_memory(registers["SP"])
                registers["SP"] += 1
        else:
            output_box.insert(tk.END, f"Error: Invalid register {reg}\n")
        clock_cycle += 10

    elif op == "ADD":
        # ADD B (means A = A + B)
        reg = args[0]
        result = registers["A"] + registers[reg]
        set_flags(result)
        registers["A"] = result & 0xFF
        clock_cycle += 4

    elif op == "SUB":
        # SUB B (means A = A - B)
        reg = args[0]
        result = registers["A"] - registers[reg]
        set_flags(result)
        registers["A"] = result & 0xFF
        clock_cycle += 4

    elif op == "INP":
        reg = args[0]
        val = simple_input_popup(f"Enter value for {reg}:")
        registers[reg] = val & 0xFF
        clock_cycle += 10

    elif op == "OUT":
        reg = args[0]
        output_box.insert(tk.END, f"{registers[reg]}\n")
        output_box.see(tk.END)
        clock_cycle += 10

    elif op == "HLT":
        halted = True
        stage_label.config(text="Stage: HALTED")

    if not halted:
        registers["PC"] += 1
        
    update_gui()

def run_program():
    global halted
    halted = False
    while not halted:
        # fetch() and execute() will handle the HLT condition.
        highlight_instruction(registers["PC"] + 1)
        instr = fetch()
        op, args = decode(instr)
        execute(op, args)

def step_program():
    global halted
    if halted:
        output_box.insert("end", "Program halted.\n")
        output_box.see("end")
        return
     
    highlight_instruction(registers["PC"] + 1)
    instr = fetch()
    op, args = decode(instr)
    execute(op, args)

def reset():
    """Resets to initial state."""
    global halted, memory, registers
    halted = True
    clock_cycle = 0
    
    # Reset all registers to default
    for key in registers:
        if key == "SP":
            registers[key] = 1024
        elif key == "FLAGS":
            registers[key] = "Z=0 S=0 P=0 C=0 AC=0"
        elif key == "IR":
            registers[key] = ""
        else:
            registers[key] = 0
    
    # Clear memory
    memory = [0] * 1024
    
    asm_text.tag_remove("highlight", "1.0", "end")

    # Clear output and stage
    output_box.delete("1.0", tk.END)
    stage_label.config(text="Stage: RESET")
    
    # Manually update GUI to reflect the reset instantly
    for r in registers:
        reg_labels[r].config(text=str(registers[r]))
    for i in range(len(memory)):
        # We need to re-read the original color, not just set text
        color = "white"
        if 0 <= i <= 255: color = "#fff8e8"
        elif 256 <= i <= 767: color = "#e8ffe8"
        elif 768 <= i <= 1023: color = "#e8f8ff"
        mem_labels[i].config(text=f"[{i:02}] = {memory[i]}", bg=color)
    root.update()

# --- Buttons --- #
btn_frame = tk.Frame(col2_frame, bg="#f0f4f7")
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="Assemble", command=assemble_program,
          bg="#cbe1ff", font=("Arial", 12, "bold"), width=10).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Run All", command=lambda: threading.Thread(target=run_program).start(),
          bg="#d4f8d4", font=("Arial", 12, "bold"), width=10).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Step", command=step_program,
          bg="#fef5d4", font=("Arial", 12, "bold"), width=10).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Reset", command=reset,
          bg="#ffcdd2", font=("Arial", 12, "bold"), width=10).grid(row=0, column=3, padx=5)


# --- Output Column ---
tk.Label(col2_frame, text="Output:", font=("Arial", 13, "bold"), bg="#f0f4f7").pack(pady=(10, 5))
output_box = tk.Text(col2_frame, height=5, width=40, font=("Consolas", 11), bg="#e8ffe8", relief="solid")
output_box.pack(pady=5)

root.mainloop()
