.PHONY: build install uninstall clean

INSTALL_DIR := $(HOME)/.pi/agent/extensions/redteam

# Build target - pi loads TypeScript directly via jiti, no compilation needed
build:
	@echo "No build step required - pi loads TypeScript directly via jiti."
	@echo "Run 'make install' to install the extension."

# Install to pi extensions directory
install:
	@echo "Installing to $(INSTALL_DIR)..."
	@mkdir -p "$(INSTALL_DIR)"
	@cp -r index.ts package.json README.md "$(INSTALL_DIR)/"
	@cp -r skills "$(INSTALL_DIR)/"
	@test -d docs && cp -r docs "$(INSTALL_DIR)/" || true
	@echo "Installed! Restart pi or run /reload to load the extension."

# Uninstall from pi extensions directory
uninstall:
	@echo "Removing $(INSTALL_DIR)..."
	@rm -rf "$(INSTALL_DIR)"
	@echo "Uninstalled. Restart pi or run /reload."

# Clean any generated files (none currently)
clean:
	@echo "Nothing to clean - pi loads TypeScript directly."
