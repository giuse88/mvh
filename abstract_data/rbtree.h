#ifndef RBTREE_H_
#define RBTREE_H_

#include "kernel.h"

#include <stddef.h>

/** Red Black tree node */
struct rb_node {
  unsigned long rb_parent_color;
#define RB_RED      0
#define RB_BLACK    1
  struct rb_node *rb_right;
  struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

/** Red Black tree root */
struct rb_root {
  struct rb_node *rb_node;
};

#define rb_parent(r) ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r) ((r)->rb_parent_color & 1)
#define rb_is_red(r) (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r) do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r) do { (r)->rb_parent_color |= 1; } while (0)

/**
 * Set node parent color in red black tree.
 *
 * @param node given node
 * @param par parent node
 */
static inline void rb_set_parent(struct rb_node *node, struct rb_node *par) {
  node->rb_parent_color = (node->rb_parent_color & 3) | (unsigned long)par;
}

/**
 * Set node color in red black tree.
 *
 * @param node given node
 * @param color color (red/black)
 */
static inline void rb_set_color(struct rb_node *node, int color) {
  node->rb_parent_color = (node->rb_parent_color & ~1) | color;
}

#define RB_ROOT (struct rb_root) { NULL, }

#define RB_EMPTY_ROOT(root) ((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node) (rb_parent(node) == node)
#define RB_CLEAR_NODE(node) (rb_set_parent(node, node))

/**
 * Initialize the tree node structure.
 *
 * @param node given node
 */
static inline void rb_init_node(struct rb_node *rb) {
  rb->rb_parent_color = 0;
  rb->rb_right = NULL;
  rb->rb_left = NULL;
  RB_CLEAR_NODE(rb);
}

/**
 * Red black tree node left rotation.
 *
 * @param node rotated node
 * @param root tree root
 */
static inline void __rb_rotate_left(struct rb_node *node, struct rb_root *root) {
  struct rb_node *right = node->rb_right;
  struct rb_node *parent = rb_parent(node);

  if ((node->rb_right = right->rb_left))
    rb_set_parent(right->rb_left, node);
  right->rb_left = node;

  rb_set_parent(right, parent);

  if (parent) {
    if (node == parent->rb_left)
      parent->rb_left = right;
    else
      parent->rb_right = right;
  }
  else
    root->rb_node = right;
  rb_set_parent(node, right);
}

/**
 * Red black tree node right rotation.
 *
 * @param node rotated node
 * @param root tree root
 */
static inline void __rb_rotate_right(struct rb_node *node, struct rb_root *root) {
  struct rb_node *left = node->rb_left;
  struct rb_node *parent = rb_parent(node);

  if ((node->rb_left = left->rb_right))
    rb_set_parent(left->rb_right, node);
  left->rb_right = node;

  rb_set_parent(left, parent);

  if (parent) {
    if (node == parent->rb_right)
      parent->rb_right = left;
    else
      parent->rb_left = left;
  }
  else
    root->rb_node = left;
  rb_set_parent(node, left);
}

/**
 * Insert node into red black tree and check colors.
 *
 * @param node inserted node
 * @param root tree root
 */
static inline void rb_insert_color(struct rb_node *node, struct rb_root *root) {
  struct rb_node *parent, *gparent;

  while ((parent = rb_parent(node)) && rb_is_red(parent)) {
    gparent = rb_parent(parent);

    if (parent == gparent->rb_left) {
      {
        register struct rb_node *uncle = gparent->rb_right;
        if (uncle && rb_is_red(uncle)) {
          rb_set_black(uncle);
          rb_set_black(parent);
          rb_set_red(gparent);
          node = gparent;
          continue;
        }
      }

      if (parent->rb_right == node) {
        register struct rb_node *tmp;
        __rb_rotate_left(parent, root);
        tmp = parent;
        parent = node;
        node = tmp;
      }

      rb_set_black(parent);
      rb_set_red(gparent);
      __rb_rotate_right(gparent, root);
    } else {
      {
        register struct rb_node *uncle = gparent->rb_left;
        if (uncle && rb_is_red(uncle)) {
          rb_set_black(uncle);
          rb_set_black(parent);
          rb_set_red(gparent);
          node = gparent;
          continue;
        }
      }

      if (parent->rb_left == node) {
        register struct rb_node *tmp;
        __rb_rotate_right(parent, root);
        tmp = parent;
        parent = node;
        node = tmp;
      }

      rb_set_black(parent);
      rb_set_red(gparent);
      __rb_rotate_left(gparent, root);
    }
  }

  rb_set_black(root->rb_node);
}

/**
 * Erase node from red black tree and check colors.
 *
 * @param node erased node
 * @param parent erased node parent
 * @param root tree root
 */
static inline void __rb_erase_color(struct rb_node *node, struct rb_node *parent, struct rb_root *root) {
  struct rb_node *other;

  while ((!node || rb_is_black(node)) && node != root->rb_node) {
    if (parent->rb_left == node) {
      other = parent->rb_right;
      if (rb_is_red(other)) {
        rb_set_black(other);
        rb_set_red(parent);
        __rb_rotate_left(parent, root);
        other = parent->rb_right;
      }
      if ((!other->rb_left || rb_is_black(other->rb_left)) &&
          (!other->rb_right || rb_is_black(other->rb_right))) {
        rb_set_red(other);
        node = parent;
        parent = rb_parent(node);
      } else {
        if (!other->rb_right || rb_is_black(other->rb_right)) {
          struct rb_node *o_left;
          if ((o_left = other->rb_left))
            rb_set_black(o_left);
          rb_set_red(other);
          __rb_rotate_right(other, root);
          other = parent->rb_right;
        }
        rb_set_color(other, rb_color(parent));
        rb_set_black(parent);
        if (other->rb_right)
          rb_set_black(other->rb_right);
        __rb_rotate_left(parent, root);
        node = root->rb_node;
        break;
      }
    } else {
      other = parent->rb_left;
      if (rb_is_red(other)) {
        rb_set_black(other);
        rb_set_red(parent);
        __rb_rotate_right(parent, root);
        other = parent->rb_left;
      }
      if ((!other->rb_left || rb_is_black(other->rb_left)) &&
          (!other->rb_right || rb_is_black(other->rb_right))) {
        rb_set_red(other);
        node = parent;
        parent = rb_parent(node);
      } else {
        if (!other->rb_left || rb_is_black(other->rb_left)) {
          register struct rb_node *o_right;
          if ((o_right = other->rb_right))
            rb_set_black(o_right);
          rb_set_red(other);
          __rb_rotate_left(other, root);
          other = parent->rb_left;
        }
        rb_set_color(other, rb_color(parent));
        rb_set_black(parent);
        if (other->rb_left)
          rb_set_black(other->rb_left);
        __rb_rotate_right(parent, root);
        node = root->rb_node;
        break;
      }
    }
  }
  if (node)
    rb_set_black(node);
}

/**
 * Erase node from red black tree
 *
 * @param node erased node
 * @param root tree root
 */
static inline void rb_erase(struct rb_node *node, struct rb_root *root) {
  struct rb_node *child, *parent;
  int color;

  if (!node->rb_left)
    child = node->rb_right;
  else if (!node->rb_right)
    child = node->rb_left;
  else {
    struct rb_node *old = node, *left;

    node = node->rb_right;
    while ((left = node->rb_left) != NULL)
      node = left;
    child = node->rb_right;
    parent = rb_parent(node);
    color = rb_color(node);

    if (child)
      rb_set_parent(child, parent);
    if (parent == old) {
      parent->rb_right = child;
      parent = node;
    } else
      parent->rb_left = child;

    node->rb_parent_color = old->rb_parent_color;
    node->rb_right = old->rb_right;
    node->rb_left = old->rb_left;

    if (rb_parent(old)) {
      if (rb_parent(old)->rb_left == old)
        rb_parent(old)->rb_left = node;
      else
        rb_parent(old)->rb_right = node;
    } else
      root->rb_node = node;

    rb_set_parent(old->rb_left, node);
    if (old->rb_right)
      rb_set_parent(old->rb_right, node);
    goto color;
  }

  parent = rb_parent(node);
  color = rb_color(node);

  if (child)
    rb_set_parent(child, parent);
  if (parent) {
    if (parent->rb_left == node)
      parent->rb_left = child;
    else
      parent->rb_right = child;
  }
  else
    root->rb_node = child;

color:
  if (color == RB_BLACK)
    __rb_erase_color(child, parent, root);
}

/**
 * Returns the first node (in sort order) of the red black tree.
 *
 * @param root tree root
 * @return node of tree
 */
static inline struct rb_node *rb_first(struct rb_root *root) {
  struct rb_node  *n;

  n = root->rb_node;
  if (!n)
    return NULL;
  while (n->rb_left)
    n = n->rb_left;
  return n;
}

/**
 * Returns the last node (in sort order) of the red black tree.
 *
 * @param root tree root
 * @return last node of tree
 */
static inline struct rb_node *rb_last(struct rb_root *root) {
  struct rb_node  *n;

  n = root->rb_node;
  if (!n)
    return NULL;
  while (n->rb_right)
    n = n->rb_right;
  return n;
}

/**
 * Returns the next node (in sort order) of the given node in red black tree.
 *
 * @param node node to look next node for
 * @return next node
 */
static inline struct rb_node *rb_next(struct rb_node *node) {
  struct rb_node *parent;

  if (rb_parent(node) == node)
    return NULL;

  /*
   * If we have a right-hand child, go down and then left as far
   * as we can.
   */
  if (node->rb_right) {
    node = node->rb_right;
    while (node->rb_left)
      node=node->rb_left;
    return node;
  }

  /* 
   * No right-hand children - everything down and left is smaller than us,
   * so any 'next' node must be in the general direction of  our parent.
   * Go up the tree; any time the ancestor is a right-hand child of its
   * parent, keep going up, first time it's a left-hand child of its
   * parent, said parent is our 'next' node.
   */
  while ((parent = rb_parent(node)) && node == parent->rb_right)
    node = parent;

  return parent;
}

/**
 * Returns the previous node (in sort order) of the given node in red black
 * tree.
 *
 * @param node node to look previous node for
 * @return previous node
 */
static inline struct rb_node *rb_prev(struct rb_node *node) {
  struct rb_node *parent;

  if (rb_parent(node) == node)
    return NULL;

  /*
   * If we have a left-hand child, go down and then right as far
   * as we can.
   */
  if (node->rb_left) {
    node = node->rb_left; 
    while (node->rb_right)
      node=node->rb_right;
    return node;
  }

  /*
   * No left-hand children. Go up till we find an ancestor which
   * is a right-hand child of its parent.
   */
  while ((parent = rb_parent(node)) && node == parent->rb_left)
    node = parent;

  return parent;
}

/**
 * Replace node in red black node.
 *
 * @param victim node to be replaced
 * @param new node that replaces @p victim node
 * @param root tree root
 */
static inline void rb_replace_node(struct rb_node *victim, struct rb_node *new, struct rb_root *root) {
  struct rb_node *parent = rb_parent(victim);

  /* Set the surrounding nodes to point to the replacement */
  if (parent) {
    if (victim == parent->rb_left)
      parent->rb_left = new;
    else
      parent->rb_right = new;
  } else {
    root->rb_node = new;
  }
  if (victim->rb_left)
    rb_set_parent(victim->rb_left, new);
  if (victim->rb_right)
    rb_set_parent(victim->rb_right, new);

  /* Copy the pointers/colour from the victim to the replacement */
  *new = *victim;
}

/**
 * Link node with given node in red black tree.
 *
 * @param node node to link
 * @param parent node parent
 * @param rb_link node to link in
 */
static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
    struct rb_node **rb_link) {
  node->rb_parent_color = (unsigned long)parent;
  node->rb_left = node->rb_right = NULL;

  *rb_link = node;
}

typedef void (*rb_augment_f)(struct rb_node *node, void *data);

static inline void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data) {
  struct rb_node *parent;

up:
  func(node, data);
  parent = rb_parent(node);
  if (!parent)
    return;

  if (node == parent->rb_left && parent->rb_right)
    func(parent->rb_right, data);
  else if (parent->rb_left)
    func(parent->rb_left, data);

  node = parent;
  goto up;
}

/*
 * After inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance.
 *
 * @param node inserted node
 * @param func augmentation function
 * @param data the associated data
 */
static inline void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data) {
  if (node->rb_left)
    node = node->rb_left;
  else if (node->rb_right)
    node = node->rb_right;

  rb_augment_path(node, func, data);
}

/**
 * Before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 *
 * @param node the node to erase
 */
static inline struct rb_node *rb_augment_erase_begin(struct rb_node *node) {
  struct rb_node *deepest;

  if (!node->rb_right && !node->rb_left)
    deepest = rb_parent(node);
  else if (!node->rb_right)
    deepest = node->rb_left;
  else if (!node->rb_left)
    deepest = node->rb_right;
  else {
    deepest = rb_next(node);
    if (deepest->rb_right)
      deepest = deepest->rb_right;
    else if (rb_parent(deepest) != node)
      deepest = rb_parent(deepest);
  }

  return deepest;
}

/**
 * After removal, update the tree to account for the removed entry
 * and any rebalance damage.
 *
 * @param node the erased node
 * @param func augmentation function
 * @param data the associated data
 */
static inline void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data) {
  if (node)
    rb_augment_path(node, func, data);
}

/**
 * Get the struct for this entry.
 *
 * @param ptr struct list head pointer
 * @param type type of the struct this is embedded in
 * @param member name of the list structure within the struct
 */
#define rb_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * Look for value in red black tree.
 *
 * @param root tree root
 * @param type type of the struct this is embedded in
 * @param member name of the list structure within the struct
 * @param key name of the key item within the struct
 * @param value value to look for in the tree
 * @param cmp comparison function
 * @return found node or NULL
 */
#define rb_find(root, type, member, key, value, cmp) ({ \
        bool found = false; \
        struct rb_node *node = root->rb_node; \
        while (node) { \
            int result = cmp(rb_entry(node, type, member)->key, value); \
            if (result < 0) { \
                node = node->rb_left; \
            } else if (result > 0) { \
                node = node->rb_right; \
            } else { \
                found = true; \
                break; \
            } \
        } \
        found ? rb_entry(node, type, member) : NULL; \
    })

/**
 * Add node to red black tree.
 *
 * @param root tree root
 * @param type type of the struct this is embedded in
 * @param member name of the list structure within the struct
 * @param key name of the key item within the struct
 * @param item item to insert into the tree
 * @param cmp comparison function
 */
#define rb_insert(root, type, member, key, item, cmp) ({ \
        bool insert = true; \
        struct rb_node **new = &(root->rb_node), *parent = NULL; \
        while (*new) { \
            int result = cmp(rb_entry(*new, type, member)->key, \
                rb_entry(item, type, member)->key); \
            parent = *new; \
            if (result < 0) { \
                new = &((*new)->rb_left); \
            } else if (result > 0) { \
                new = &((*new)->rb_right); \
            } else { \
                insert = false; \
                break; \
            } \
        } \
        if (insert) { \
            rb_link_node(item, parent, new); \
            rb_insert_color(item, root); \
        } \
    })

/**
 * Delete node with given value from red black tree.
 *
 * @param root tree root
 * @param type type of the struct this is embedded in
 * @param member name of the list structure within the struct
 * @param key name of the key item within the struct
 * @param value value to delete from tree
 * @param cmp comparison function
 */
#define rb_delete(root, type, member, key, value, cmp) ({ \
        struct rb_node *node = rb_find(root, type, member, key, value, cmp); \
        if (node) { \
            rb_erase(node, root); \
        } \
    })

/**
 * Iterate over a red black tree.
 *
 * @param pos struct tree node to use as a loop counter
 * @param root root for your tree
 */
#define rb_for_each(pos, root) \
    for (pos = rb_first(root); pos; pos = rb_next(pos))

/**
 * Iterate over a red black tree backwards.
 *
 * @param pos struct tree node to use as a loop counter
 * @param root root for your tree
 */
#define rb_for_each_prev(pos, root) \
    for (pos = rb_last(root); pos; pos = rb_prev(pos))

/**
 * Iterate over a red black tree safe against removal of list entry
 *
 * @param pos struct tree node to use as a loop counter
 * @param n another struct list head to use as temporary storage
 * @param root the root for your tree
 */
#define rb_for_each_safe(pos, n, root) \
    for (pos = rb_first(root); pos && ({ n = rb_next(pos); 1; }); \
         pos = n)

/**
 * Iterate over red black tree of given type.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos node pointer to use as a loop cursor
 * @param root root for your tree
 * @param member name of the tree structure within the struct
 */
#define rb_for_each_entry(tpos, pos, root, member) \
    for (pos = rb_first(root); \
         pos && ({ tpos = rb_entry(pos, typeof(*tpos), member); 1;}); \
         pos = rb_next(pos))

/**
 * Iterate over list of given type safe against removal of list entry.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos struct tree node to use as a loop counter
 * @param n another type pointer to use as temporary storage
 * @param root root for your tree
 * @param member name of the tree structure within the struct
 */
#define rb_for_each_entry_safe(tpos, pos, n, root, member) \
    for (pos = rb_first(root); \
         pos && ({ n = rb_next(pos); 1; }) && ({ tpos = rb_entry(pos, typeof(*tpos), member); 1;}); \
         pos = n)

#endif /* RBTREE_H_ */
