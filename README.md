# Visual RISC Simulator (8085-Based)

A visual RISC (Reduced Instruction Set Computing) simulator with a graphical user interface (GUI) built using Python and Tkinter.

This simulator models a simple RISC CPU but uses the **register set (A, B, C, D, E, H, L, SP, PC)** and instruction mnemonics of the **Intel 8085** as its architectural base. It allows you to write, assemble, and execute assembly code while visualizing the CPU's internal state, memory, and clock cycle execution.

## Features

  - **Interactive GUI** using Tkinter in a three-column layout.
  - **8085-Based Register Set:** Real-time visualization of `A`, `B`, `C`, `D`, `E`, `H`, `L`, `SP`, `PC`, `FLAGS`, and `IR`.
  - **1KB (1024-byte) Memory:**
      - **Color-Coded Memory Map** to visually distinguish Code (yellow), Data (green), and Stack (blue) sections.
      - **Memory Navigation** controls (`Go to`, `Next`, `Prev`) to instantly inspect any part of memory.
  - **Assembly Code Editor** with instruction highlighting during execution.
  - **CPU Control:**
      - `Assemble`: Load the program into memory.
      - `Run All`: Execute the program at full speed (with a slight delay for visualization).
      - `Step`: Execute one instruction at a time.
      - `Reset`: Clears all registers, memory, and state.
  - **Clock Cycle Counter** to track the simulated execution time of your code.
  - **Stack Boundary Detection** with "Stack Overflow" and "Stack Underflow" error reporting.
  - **Visual CPU State** display (`FETCH`, `DECODE`, `EXECUTE`, `HALTED`).

## Visual Layout

The simulator is organized into three columns for a clean workspace:

  * **Column 1:** Displays all 8085 registers and the running Clock Cycle count.
  * **Column 2:** Contains the Assembly Code Input, control buttons (Assemble, Run All, Step, Reset), the Output console, and the current CPU Stage.
  * **Column 3:** Shows the full 1KB memory, the color-coded legend, and navigation controls.

## Usage

1.  Run the simulator:
    ```bash
    python your_simulator_filename.py
    ```
2.  Enter your 8085-like assembly code in the "Assembly Code Input" box.
3.  Click **Assemble** to load your program into memory.
4.  Use **Run All** to execute the full program or **Step** for single-step execution.
5.  Click **Reset** to return the simulator to its initial state.

## Supported Instructions (8085-like)

This simulator supports a **reduced instruction set** that uses 8085 mnemonics.

### Data Transfer

  - `MVI R, val` (e.g., `MVI A, 50`): Move an immediate 8-bit value into a register.
  - `STA addr` (e.g., `STA 300`): Store the Accumulator's (A) value at a memory address.
  - `LDA addr` (e.g., `LDA 300`): Load the Accumulator (A) with the value from a memory address.

### Arithmetic

  - `ADD R` (e.g., `ADD B`): Add register `R` to the Accumulator (`A = A + R`).
  - `SUB R` (e.g., `SUB C`): Subtract register `R` from the Accumulator (`A = A - R`).

### Stack & I/O

  - `PUSH R` (e.g., `PUSH B`): Push a register's value onto the stack.
  - `POP R` (e.g., `POP D`): Pop a value from the stack into a register.
  - `INP R` (e.g., `INP A`): **(Simulated)** Show a popup to get an input value for a register.
  - `OUT R` (e.g., `OUT B`): **(Simulated)** Print a register's value to the Output box.

### Control

  - `HLT`: Halt program execution.