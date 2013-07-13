#ifndef X86_DECODER_H
#define X86_DECODER_H

#include <stdbool.h>

enum {
  REX_B = 0x01,
  REX_X = 0x02,
  REX_R = 0x04,
  REX_W = 0x08
};

extern unsigned short next_inst(const char **ip, bool is64bit, bool *has_prefix,
    char **rex_ptr, char **mod_rm_ptr, char **sib_ptr, bool *is_group);

#endif // X86_DECODER_H
