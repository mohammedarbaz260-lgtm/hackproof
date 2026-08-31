from pathlib import Path

p = Path("main.py")
s = p.read_text()

target = '    user_input = input("You: ")\n'

insert = '''    user_input = input("You: ")

    tool_result = handle_tool_request(user_input)

    if tool_result is not None:
        answer = "Safe tool result:\\n" + tool_result
        memory_entry = f"\\nUser: {user_input}\\nHackProof: {answer}\\n"

        with open("memory.txt", "a", encoding="utf-8") as f:
            f.write(memory_entry)

        print("\\nHackProof:", answer)
        print()
        continue
'''

if target not in s:
    print("TARGET NOT FOUND")
    raise SystemExit(1)

s = s.replace(target, insert, 1)
p.write_text(s)

print("Tool connection added successfully.")
