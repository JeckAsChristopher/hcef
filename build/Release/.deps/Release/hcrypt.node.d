cmd_Release/hcrypt.node := ln -f "Release/obj.target/hcrypt.node" "Release/hcrypt.node" 2>/dev/null || (rm -rf "Release/hcrypt.node" && cp -af "Release/obj.target/hcrypt.node" "Release/hcrypt.node")
