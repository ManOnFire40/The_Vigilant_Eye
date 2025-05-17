import customtkinter as ctk

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("300x150")
label = ctk.CTkLabel(app, text="Test Window")
label.pack(pady=20)
# Set a custom navy blue color for the main background
NAVY_BLUE = "#001f4d"
app.configure(bg=NAVY_BLUE)

# Make the window size flexible and responsive
app.geometry("900x600")
app.minsize(600, 400)

# Configure grid layout for flexibility
app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=1)

# Create a sidebar frame
sidebar = ctk.CTkFrame(app, width=150, fg_color=NAVY_BLUE)
sidebar.grid(row=0, column=0, sticky="ns")

# Add tab buttons to the sidebar
abuse_ipdb_btn = ctk.CTkButton(sidebar, text="Abuse IPDB")
abuse_ipdb_btn.pack(pady=10, fill="x")

virus_total_btn = ctk.CTkButton(sidebar, text="Virus total")
virus_total_btn.pack(pady=10, fill="x")

ipinfo_btn = ctk.CTkButton(sidebar, text="IPinfo")
ipinfo_btn.pack(pady=10, fill="x")

# Main content area (placeholder)
main_content = ctk.CTkFrame(app, fg_color=NAVY_BLUE)
main_content.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
if __name__ == "__main__":
	app.mainloop()