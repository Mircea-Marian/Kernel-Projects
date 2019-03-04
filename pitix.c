#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>

#include "pitix.h"
#define PITIX_SUPER_BLOCK           0

struct pitix_sb_info {
    __u8 version;
    __u8 block_size_bits;
    __u8 imap_block;
    __u8 dmap_block;
    __u8 izone_block;
    __u8 dzone_block;
    __u16 bfree;
    __u16 ffree;
    struct mutex pitix_lock;
#ifdef __KERNEL__
    struct buffer_head *sb_bh, *dmap_bh, *imap_bh;
    __u8 *dmap, *imap;
#endif
};

struct pitix_inode_info {
    __u16 direct_data_blocks[INODE_DIRECT_DATA_BLOCKS];
    __u16 indirect_data_block;
    struct inode vfs_inode;
};
//// start inode stuff

struct inode *pitix_new_inode(struct super_block *s)
{
    struct pitix_inode_info *mii;
    int a;

    mii = kzalloc(sizeof(struct pitix_inode_info), GFP_KERNEL);
    if (mii == NULL)
        return NULL;

    for(a = 0; a < INODE_DIRECT_DATA_BLOCKS; a++)
        mii->direct_data_blocks[a] = 0;
    mii->indirect_data_block = 0;

    inode_init_once(&mii->vfs_inode);

    return &mii->vfs_inode;
}

void pitix_evict_inode(struct inode *inode)
{
    kfree(container_of(inode, struct pitix_inode_info, vfs_inode));
    // truncate_inode_pages_final(&inode->i_data);
    // invalidate_inode_buffers(inode);
    clear_inode(inode);
}

int pitix_write_inode(struct inode *inode,
        struct writeback_control *wbc)
{
    struct pitix_inode *pi;
    struct pitix_inode_info *pii = container_of(inode,
            struct pitix_inode_info, vfs_inode);
    struct buffer_head *bh;
    int err = 0, a;
    char n = INODE_DIRECT_DATA_BLOCKS;
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)inode->i_sb->s_fs_info;

    bh = sb_bread(inode->i_sb, sbi->izone_block +
        inode->i_ino / pitix_inodes_per_block(inode->i_sb));
    if (bh == NULL) {
        err = -ENOMEM;
        goto out;
    }

    pi = (struct pitix_inode *)(bh->b_data +
        inode_size() * (inode->i_ino % pitix_inodes_per_block(inode->i_sb)));

    /* fill disk inode */
    pi->mode = inode->i_mode;
    i_uid_write(inode, pi->uid);
    i_gid_write(inode, pi->gid);
    pi->size = inode->i_size;
    for(a = 0 ; a < INODE_DIRECT_DATA_BLOCKS ; a++)
        pi->direct_data_blocks[a] = pii->direct_data_blocks[a];
    pi->indirect_data_block = pii->indirect_data_block;

    mark_buffer_dirty(bh);
    brelse(bh);

out:
    return err;
}

static void pitix_put_super(struct super_block *sb)
{
    struct pitix_sb_info *sbi = sb->s_fs_info;

    /* Free superblock buffer head. */
    mutex_destroy(&sbi->pitix_lock);
    mark_buffer_dirty(sbi->sb_bh);
    mark_buffer_dirty(sbi->dmap_bh);
    mark_buffer_dirty(sbi->imap_bh);
    brelse(sbi->sb_bh);
    brelse(sbi->dmap_bh);
    brelse(sbi->imap_bh);

    // dprintk("released superblock resources\n");
}

static int compareNames(const char *s1, const char *s2)
{
    int n = PITIX_NAME_LEN;

    while(n--){

        if(*s1 == '\0' && *s2 == '\0')
            break;

        if(*s1 != *s2)
            return 1;

        s1++;
        s2++;
    }
    return 0;
}

static struct buffer_head *pitix_find_entry(struct inode *dir,
    struct pitix_dir_entry **dde, const char *name)
{
    struct pitix_inode_info *mii = container_of(dir,
            struct pitix_inode_info, vfs_inode);
    struct pitix_dir_entry *de;
    int i = dir_entries_per_block(dir->i_sb);
    struct buffer_head *bh;
    ino_t rez;
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)
        dir->i_sb->s_fs_info;

    // // pr_info("pitix_find_entry: entered\n");

    *dde = NULL;

    // // pr_info("pitix_find_entry: before sb_bread call");

    bh = sb_bread(dir->i_sb,
        sbi->dzone_block + mii->direct_data_blocks[0]);

    de = (struct pitix_dir_entry *)bh->b_data;
    while(i--){

        // // pr_info("pitix_find_entry: it.name=%s target=%s",
        //     de->name, name);
        // if(!strcmp(de->name, name)){
        if(!compareNames(de->name, name)) {
            rez = de->ino;
            *dde = de;
            break;
        }

        de++;
    }

    return bh;
}

ino_t pitix_inode_by_name(struct dentry *dentry, int delete)
{
    struct buffer_head *bh;
    struct inode *dir = dentry->d_parent->d_inode;
    struct pitix_inode_info *mii = container_of(dir,
            struct pitix_inode_info, vfs_inode);
    struct super_block *sb = dir->i_sb;
    struct pitix_dir_entry *de = NULL;

    // // pr_info("pitix_inode_by_name: entered\n");

    bh = pitix_find_entry(dir, &de, dentry->d_name.name);
    // // pr_info("pitix_inode_by_name: bh=%p", bh);


    if(!bh || !de){
        // pr_info("pitix_inode_by_name: fail");
        brelse(bh);
        return 0;
    }
    brelse(bh);
    return (ino_t)de->ino;
}

static struct dentry *pitix_lookup(struct inode *dir,
        struct dentry *dentry, unsigned int flags)
{
    struct inode *inode = NULL;
    ino_t ino;

    pr_emerg("pitix_lookup: enterd lookup for %s\n", dentry->d_name.name);

    if (dentry->d_name.len >= PITIX_NAME_LEN)
        return ERR_PTR(-ENAMETOOLONG);

    // // pr_info("pitix_lookup: before pitix_inode_by_name call");

    ino = pitix_inode_by_name(dentry, 0);
    if (ino) {
        inode = pitix_iget(dir->i_sb, ino);
        if (IS_ERR(inode)) {
            pr_err("Cannot read inode %lu", (unsigned long)ino);
            return ERR_PTR(PTR_ERR(inode));
        }
        d_add(dentry, inode);
        // // pr_info("pitix_lookup %d: Found the file!\n", aaaa);
    }
    pr_emerg("pitix_lookup: exited %s\n", dentry->d_name.name);
    return NULL;
}

static int pitix_unlink(struct inode * dir, struct dentry *dentry)
{
    int error = -ENOENT;
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh;
    struct pitix_dir_entry *de;
    struct pitix_sb_info *info = inode->i_sb->s_fs_info;
    struct pitix_inode *pi;

    // mutex_lock(&info->pitix_lock);
    bh = pitix_find_entry(dir, &de, dentry->d_name.name);
    if (!bh || de->ino != inode->i_ino)
        goto out_brelse;

    if (!inode->i_nlink)
        set_nlink(inode, 1);
    de->ino = 0;
    mark_buffer_dirty_inode(bh, dir);
    dir->i_ctime = dir->i_mtime = current_time(dir);
    mark_inode_dirty(dir);
    inode->i_ctime = dir->i_ctime;
    inode_dec_link_count(inode);
    error = 0;

out_brelse:
    brelse(bh);
    // mutex_unlock(&info->pitix_lock);
    return error;
}

static int pitix_add_entry(struct inode *dir, const unsigned char *name,
                            int ino)
{
    struct buffer_head *bh;
    struct pitix_dir_entry *de;
    struct super_block *sb = dir->i_sb;
    struct pitix_inode_info *pii = container_of(dir,
        struct pitix_inode_info, vfs_inode);
    int i = dir_entries_per_block(sb), new_size = 0;
    int a;
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)
        sb->s_fs_info;

    bh = sb_bread(sb, sbi->dzone_block + pii->direct_data_blocks[0]);

    de = (struct pitix_dir_entry *)bh->b_data;
    while(i--){

        if(!de->ino) {
            de->ino = (__u32)ino;
            new_size += dir_entry_size();
            if(new_size >= dir->i_size) {
                dir->i_size += dir_entry_size();
                dir->i_ctime = current_time(dir);
            }
            dir->i_mtime = current_time(dir);
            mark_inode_dirty(dir);
            for(a = 0 ; a < PITIX_NAME_LEN ; a++) {
                de->name[a] = name[a];
                if(name[a] == '\0')
                    break;
            }
            mark_buffer_dirty_inode(bh, dir);
            brelse(bh);
            return 0;
        }

        de++;
        new_size += dir_entry_size();
    }
    brelse(bh);
    return -ENOSPC;
}

int pitix_alloc_inode(struct super_block *sb)
{
    int ino;
    struct pitix_sb_info *info = sb->s_fs_info;

    ino = find_first_zero_bit((long unsigned int *)info->imap_bh->b_data, sb->s_blocksize_bits);
    if (ino < sb->s_blocksize_bits)
        set_bit(ino, (long unsigned int *)info->imap_bh->b_data);

    return ino;
}

int pitix_alloc_block(struct super_block *sb)
{
    int ino;
    struct pitix_sb_info *info = sb->s_fs_info;

    ino = find_first_zero_bit((long unsigned int *)info->dmap_bh->b_data, sb->s_blocksize_bits);
    if (ino < sb->s_blocksize_bits)
        set_bit(ino, (long unsigned int *)info->dmap_bh->b_data);

    return ino;
}

void pitix_free_block(struct super_block *sb, int block)
{
    struct pitix_sb_info *info = sb->s_fs_info;
    clear_bit(block, (long unsigned int *)info->dmap_bh->b_data);
}

void pitix_free_inode(struct super_block *sb, int block)
{
    struct pitix_sb_info *info = sb->s_fs_info;
    clear_bit(block, (long unsigned int *)info->imap_bh->b_data);
}

int pitix_get_block(struct inode *inode, sector_t block,
        struct buffer_head *bh_result, int create)
{
    struct super_block *sb = inode->i_sb;
    struct pitix_inode_info *pi = container_of(inode,
        struct pitix_inode_info, vfs_inode);
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)sb->s_fs_info;
    int a, storeBlockLoc = -1, pos, b;
    struct buffer_head *bh;
    __u16 *it;

    for(a = 0; a < INODE_DIRECT_DATA_BLOCKS; a++) {
        if(pi->direct_data_blocks[a] == block) {
            map_bh(bh_result, sb, sbi->dzone_block + block);
            return 0;
        }
        if(storeBlockLoc == -1 && !pi->direct_data_blocks[a]) {
            storeBlockLoc = 0;
            pos = a;
        }
    }
    if(pi->indirect_data_block) {
        bh = sb_bread(sb, sbi->dzone_block + pi->indirect_data_block);
        a = 0;
        b = sb->s_blocksize / sizeof(__u16);
        it = (__u16*)bh->b_data;
        while(a < b) {
            if(block == *it) {
                map_bh(bh_result, sb, sbi->dzone_block + block);
                brelse(bh);
                return 0;
            }

            if(storeBlockLoc == -1 && *it == 0) {
                storeBlockLoc = 1;
                pos = a;
            }

            it++;
            a++;
        }
        brelse(bh);
    }
    if(!create || test_and_set_bit(block, (long unsigned int *)sbi->dmap_bh->b_data))
        return -1;
    if(storeBlockLoc == -1) {
        clear_bit(block, (long unsigned int *)sbi->dmap_bh->b_data);
        return -1;
    }
    bh = sb_bread(sb, sbi->dzone_block + block);
    memset(bh->b_data, 0, sb->s_blocksize);
    mark_buffer_dirty(bh);
    brelse(bh);
    map_bh(bh_result, sb, sbi->dzone_block + block);
    if(storeBlockLoc == 0) {
        pi->direct_data_blocks[pos] = block;
        return 0;
    }
    bh = sb_bread(sb, sbi->dzone_block + pi->indirect_data_block);
    *( (__u16*)(bh->b_data + sizeof(__u16) * pos) ) = block;
    mark_buffer_dirty(bh);
    brelse(bh);
    return 0;
}

static int pitix_mkdir(struct inode * dir, struct dentry * dentry, umode_t mode)
{
    int err, a;
    struct inode *inode;
    struct super_block *s = dir->i_sb;
    struct pitix_sb_info *info = s->s_fs_info;
    unsigned long ino, dbno;
    struct pitix_inode_info *pii;
    struct buffer_head *bh;
    // struct buffer_head bh;

    // pr_info("entered pitix_mkdir: %s !\n", dentry->d_name.name);

    inode = new_inode(s);
    if (!inode)
        return -ENOMEM;
    // mutex_lock(&info->pitix_lock);
    ino = pitix_alloc_inode(s);
    if (ino > s->s_blocksize_bits) {
        // mutex_unlock(&info->pitix_lock);
        iput(inode);
        return -ENOSPC;
    }
    dbno = pitix_alloc_block(s);
    if (dbno > s->s_blocksize_bits) {
        pitix_free_inode(s, ino);
        // mutex_unlock(&info->pitix_lock);
        iput(inode);
        return -ENOSPC;
    }

    // // pr_info("alloced: ino=%u dbno=%u\n", ino, dbno);
    // // pr_info("pitix_mkdir: pitix_dir_inode_operations=%p\n", pitix_dir_inode_operations);

    // Wipe the data block.
    bh = sb_bread(s, info->dzone_block + dbno);
    memset(bh->b_data, 0, s->s_blocksize);
    mark_buffer_dirty(bh);
    brelse(bh);

    info->ffree--;
    inode_init_owner(inode, dir, S_IFDIR | mode);
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
    inode->i_blocks = 0;
    inode->i_op = &pitix_dir_inode_operations;
    inode->i_fop = &pitix_dir_operations;
    inode->i_mapping->a_ops = &pitix_aops;
    inode->i_ino = ino;

    // i_uid_write(inode, dir->i_uid);
    // i_gid_write(inode, dir->i_gid);

    inode_inc_link_count(inode);

    pii = container_of(inode, struct pitix_inode_info, vfs_inode);
    pii->direct_data_blocks[0] = dbno;
    for(a = 1 ; a < INODE_DIRECT_DATA_BLOCKS ; a++)
        pii->direct_data_blocks[a] = 0;
    pii->indirect_data_block = 0;

    // pitix_get_block(inode, dbno, &bh, 1);

    // // pr_info("pii = %p, &pii->vfs_inode = %p, &inode = %p\n",
    //     &(pii->vfs_inode), &inode, pii);

    insert_inode_hash(inode);
    mark_inode_dirty(inode);
    // bfs_dump_imap("create", s); debug

    err = pitix_add_entry(dir, dentry->d_name.name,
                            inode->i_ino);
    if (err) {
        inode_dec_link_count(inode);
        pitix_free_block(s, dbno);
        pitix_free_inode(s, ino);
        // mutex_unlock(&info->pitix_lock);
        iput(inode);
        return err;
    }

    // // pr_info("After pitix_add_entry call and eval !\n");

    // mutex_unlock(&info->pitix_lock);
    d_instantiate(dentry, inode);

    // pr_info("Succesfull mkdir: %s !\n", dentry->d_name.name);

    return 0;
}

static int pitix_rmdir(struct inode * dir, struct dentry *dentry)
{
    int error = -ENOENT, block, off;
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh, *bh1, *bh2;
    struct pitix_dir_entry *de, *itDE;
    struct pitix_sb_info *info = inode->i_sb->s_fs_info;
    struct pitix_inode *pi, *itPI;
    int n = dir_entries_per_block(inode->i_sb)-1;

    // pr_info("Entered pitix_rmdir: %s !\n", dentry->d_name.name);

    // mutex_lock(&info->pitix_lock);
    bh = pitix_find_entry(dir, &de, dentry->d_name.name);
    if (!bh || de->ino != inode->i_ino){
        // // pr_info("pitix_rmdir: first out_brelse\n");
        goto out_brelse;
    }

    // // pr_info("pitix_rmdir: pitix_empty_dir=%d\n", pitix_empty_dir(de, bh));

    block = de->ino / pitix_inodes_per_block(inode->i_sb);
    off = inode_size() * (de->ino % pitix_inodes_per_block(inode->i_sb));
    bh1 = sb_bread(inode->i_sb, info->izone_block + block);
    pi = (struct pitix_inode *)(bh1->b_data + off);
    bh2 = sb_bread(inode->i_sb, info->dzone_block + pi->direct_data_blocks[0]);
    itDE = (struct pitix_dir_entry *)(bh2->b_data + 2 * dir_entry_size());
    while(n--) {
        if(itDE->ino) {
            error = -ENOTEMPTY;
            brelse(bh2);
            brelse(bh1);
            // // pr_info("pitix_rmdir: second out_brelse, found->%d\n",
            //     (int)((struct pitix_dir_entry *)bh2->b_data+ dir_entry_size())->ino);
            goto out_brelse;
        }
        itDE++;
    }

    // if(((struct pitix_dir_entry *)bh2->b_data + dir_entry_size())->ino) {
    //     error = -ENOTEMPTY;
    //     brelse(bh2);
    //     brelse(bh1);
    //     // // pr_info("pitix_rmdir: second out_brelse, found->%d\n",
    //     //     (int)((struct pitix_dir_entry *)bh2->b_data+ dir_entry_size())->ino);
    //     goto out_brelse;
    // }

    pitix_free_inode(inode->i_sb, de->ino);
    pitix_free_block(inode->i_sb, pi->direct_data_blocks[0]);

    brelse(bh2);
    brelse(bh1);

    if (!inode->i_nlink)
        set_nlink(inode, 1);
    de->ino = 0;
    mark_buffer_dirty_inode(bh, dir);
    dir->i_ctime = dir->i_mtime = current_time(dir);
    mark_inode_dirty(dir);
    inode->i_ctime = dir->i_ctime;
    inode_dec_link_count(inode);
    error = 0;

out_brelse:
    brelse(bh);
    // mutex_unlock(&info->pitix_lock);
    return error;
}

static int pitix_readdir(struct file *f, struct dir_context *ctx)
{
    struct inode *dir = file_inode(f);
    struct buffer_head *bh;
    struct pitix_dir_entry *de;
    struct pitix_inode_info *pi = container_of(dir,
        struct pitix_inode_info, vfs_inode);
    unsigned int offset = 0;
    int block;
    struct pitix_sb_info *info = (struct pitix_sb_info *)
        dir->i_sb->s_fs_info;

    // pr_info("pitix_readdir: entered\n");

    if (ctx->pos & (dir_entry_size() - 1)) {
        // printf("Bad f_pos=%08lx for %s:%08lx\n",
        //             (unsigned long)ctx->pos,
        //             dir->i_sb->s_id, dir->i_ino);
        return -EINVAL;
    }

    while (ctx->pos < dir->i_size) {;
        bh = sb_bread(dir->i_sb, info->dzone_block
            + pi->direct_data_blocks[0]);
        do {
            de = (struct pitix_dir_entry *)(bh->b_data + offset);
            if (de->ino) {
                int size = strnlen(de->name, PITIX_NAME_LEN);
                if (!dir_emit(ctx, de->name, size,
                        le16_to_cpu(de->ino),
                        DT_UNKNOWN)) {
                    brelse(bh);
                    return 0;
                }
            }
            offset += dir_entry_size();
            ctx->pos += dir_entry_size();
        } while ((offset < dir->i_sb->s_blocksize) && (ctx->pos < dir->i_size));
        brelse(bh);
    }
    return 0;
}

static int pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode,
        bool excl)
{
    int err, a;
    struct inode *inode;
    struct super_block *s = dir->i_sb;
    struct pitix_sb_info *info = s->s_fs_info;
    unsigned long ino;
    struct pitix_inode_info *pii;
    struct buffer_head *bh;

    pr_emerg("pitix_create: entered for %s\n", dentry->d_name.name);

    if(info->ffree == 0)
        return -ENOSPC;

    inode = new_inode(s);
    if (!inode)
        return -ENOMEM;
    // // mutex_lock(&info->pitix_lock);
    ino = pitix_alloc_inode(s);
    if (ino > s->s_blocksize_bits) {
        // // mutex_unlock(&info->pitix_lock);
        iput(inode);
        return -ENOSPC;
    }

    info->ffree--;
    inode_init_owner(inode, dir, mode);
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
    inode->i_blocks = 0;
    inode->i_op = &pitix_file_inode_operations;
    inode->i_fop = &pitix_file_operations;
    inode->i_mapping->a_ops = &pitix_aops;
    inode->i_ino = ino;
    pii = container_of(inode, struct pitix_inode_info, vfs_inode);
    pii->direct_data_blocks[0] = 0;
    for(a = 1 ; a < INODE_DIRECT_DATA_BLOCKS ; a++)
        pii->direct_data_blocks[a] = 0;
    pii->indirect_data_block = 0;
    insert_inode_hash(inode);
    mark_inode_dirty(inode);
    // bfs_dump_imap("create", s); debug

    err = pitix_add_entry(dir, dentry->d_name.name,
                            inode->i_ino);
    if (err) {
        pitix_free_inode(s, ino);
        inode_dec_link_count(inode);
        // mutex_unlock(&info->pitix_lock);
        iput(inode);
        return err;
    }
    // mutex_unlock(&info->pitix_lock);
    d_instantiate(dentry, inode);
    pr_emerg("pitix_create: exited with 0 for %s\n", dentry->d_name.name);
    return 0;
}

static int pitix_setattr(struct dentry *dentry, struct iattr *attr)
{
    struct inode *inode = d_inode(dentry);
    struct super_block *sb = inode->i_sb;
    int error, a, offset;
    unsigned int old_size = i_size_read(inode), new_size = attr->ia_size,
        old_num_of_blocks = (old_size % sb->s_blocksize)?
            (old_size / sb->s_blocksize + 1) : (old_size / sb->s_blocksize),
        new_num_of_blocks = (new_size % sb->s_blocksize)?
            (new_size / sb->s_blocksize + 1) : (new_size / sb->s_blocksize),
            diff, last_block_no;
    struct pitix_inode_info *pi;
    unsigned short dbno;
    struct buffer_head *bh;
    char flag;
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)
        sb->s_fs_info;

    pr_emerg("pitix_setattr: entered for %s\n", dentry->d_name.name);

    error = setattr_prepare(dentry, attr);
    if (error)
        return error;

    if ((attr->ia_valid & ATTR_SIZE) &&
        attr->ia_size != i_size_read(inode)) {
        error = inode_newsize_ok(inode, attr->ia_size);
        if (error)
            return error;

        pr_emerg("after error check\n");
        truncate_setsize(inode, attr->ia_size);
        if(S_ISREG(inode->i_mode)){
            pi = container_of(inode, struct pitix_inode_info, vfs_inode);
            if(old_size < new_size) {
                if(old_num_of_blocks - 1 < INODE_DIRECT_DATA_BLOCKS) {
                    bh = sb_bread(sb, sbi->dzone_block
                        + pi->direct_data_blocks[old_num_of_blocks - 1]);
                } else {
                    bh = sb_bread(sb, sbi->dzone_block
                        + pi->indirect_data_block);
                    old_num_of_blocks -= INODE_DIRECT_DATA_BLOCKS;
                    last_block_no = *((__u16 *)(bh->b_data + sizeof(__u16) * (old_num_of_blocks - 1)));
                    brelse(bh);
                    old_num_of_blocks += INODE_DIRECT_DATA_BLOCKS;
                    bh = sb_bread(sb, sbi->dzone_block
                        + last_block_no);
                }
                if(new_num_of_blocks == old_num_of_blocks) {
                    memset(bh->b_data + old_size % sb->s_blocksize, 0, new_size - old_size);
                    mark_buffer_dirty(bh);
                    brelse(bh);
                } else {
                    memset(bh->b_data + old_size % sb->s_blocksize, 0, sb->s_blocksize
                        - old_size % sb->s_blocksize);
                    mark_buffer_dirty(bh);
                    brelse(bh);
                    diff = new_num_of_blocks - old_num_of_blocks;
                    for(a = 0 ; a < INODE_DIRECT_DATA_BLOCKS ; a++) {
                        if(!diff)
                            break;
                        if(!pi->direct_data_blocks[a]) {

                            dbno = pitix_alloc_block(sb);
                            if(dbno > sb->s_blocksize_bits)
                                return -ENOSPC;
                            pi->direct_data_blocks[a] = dbno;

                            diff--;
                        }
                    }
                    if(diff) {
                        if(!pi->indirect_data_block) {
                            dbno = pitix_alloc_block(sb);
                            if(dbno > sb->s_blocksize_bits)
                                return -ENOSPC;
                            pi->indirect_data_block = dbno;
                            bh = sb_bread(sb, sbi->dzone_block + dbno);
                            memset(bh->b_data, 0, sb->s_blocksize);
                            mark_buffer_dirty(bh);
                            brelse(bh);
                        }
                        bh = sb_bread(sb, sbi->dzone_block + pi->indirect_data_block);
                        offset = 0;
                        while(offset < sb->s_blocksize){
                            if(!diff)
                                break;
                            dbno = pitix_alloc_block(sb);
                            if(dbno > sb->s_blocksize_bits)
                                return -ENOSPC;
                            *((__u16 *)(bh->b_data + offset)) = dbno;

                            diff--;
                            offset += sizeof(__u16);
                        }
                        mark_buffer_dirty(bh);
                        brelse(bh);

                        if(diff)
                            return -ENOSPC;
                    }
                }
            } else {
                if(old_num_of_blocks != new_num_of_blocks) {
                    diff = old_num_of_blocks - new_num_of_blocks;
                    if(old_num_of_blocks > INODE_DIRECT_DATA_BLOCKS) {
                        bh = sb_bread(sb, sbi->dzone_block
                            + pi->indirect_data_block);
                        old_num_of_blocks -= INODE_DIRECT_DATA_BLOCKS;
                        offset = sizeof(__u16) * (old_num_of_blocks - 1);
                        old_num_of_blocks += INODE_DIRECT_DATA_BLOCKS;
                        while(old_num_of_blocks != new_num_of_blocks
                            && offset >= 0) {

                            pitix_free_block(sb,  *((__u16 *)(bh->b_data + offset)));
                            *((__u16 *)(bh->b_data + offset)) = 0;

                            old_num_of_blocks--;
                            offset -= sizeof(__u16);
                        }
                        mark_buffer_dirty(bh);
                        if(*((__u16 *)(bh->b_data)) == 0) {
                            pitix_free_block(sb, pi->indirect_data_block);
                            pi->indirect_data_block = 0;
                        }
                        brelse(bh);
                    }
                    if(old_num_of_blocks != new_num_of_blocks) {
                        for(a = INODE_DIRECT_DATA_BLOCKS - 1 ; a >= 0 ; a--) {
                            pitix_free_block(sb, pi->direct_data_blocks[a]);
                            pi->direct_data_blocks[a] = 0;
                            if(old_num_of_blocks == new_num_of_blocks)
                                break;
                        }
                    }
                }
            }
        }
    }

    setattr_copy(inode, attr);
    mark_inode_dirty(inode);
    return 0;
}

static int pitix_getattr(const struct path *path, struct kstat *stat,
          u32 request_mask, unsigned int flags)
{
    struct super_block *sb = path->dentry->d_sb;
    struct inode *inode = d_inode(path->dentry);
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)
        sb->s_fs_info;
    struct buffer_head *bh;
    struct pitix_inode_info *pii = container_of(
        inode, struct pitix_inode_info, vfs_inode);
    int a;

    generic_fillattr(inode, stat);

    stat->blocks = 0;

    for(a = 0 ; a < INODE_DIRECT_DATA_BLOCKS ; a++)
        if(pii->direct_data_blocks)
            stat->blocks++;
    if(pii->indirect_data_block) {
        bh = sb_bread(sb, sbi->dzone_block
            + pii->indirect_data_block);

        for(a = 0; a < sb->s_blocksize ; a += sizeof(__u16))
            if( *( (__u16*)(bh->b_data + a) ) )
                stat->blocks++;

        brelse(bh);
    }

    stat->blksize = sb->s_blocksize;
    return 0;
}

struct inode_operations pitix_dir_inode_operations = {
    .create     = pitix_create,
    .lookup     = pitix_lookup,
    .unlink     = pitix_unlink,
    .mkdir      = pitix_mkdir,
    .rmdir      = pitix_rmdir,
};
struct file_operations pitix_dir_operations = {
    .read       = generic_read_dir,
    .iterate    = pitix_readdir,
};

struct file_operations pitix_file_operations = {
    .llseek     = generic_file_llseek,
    .read_iter  = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
    .mmap       = generic_file_mmap,
    .splice_read    = generic_file_splice_read,
};
struct inode_operations pitix_file_inode_operations = {
    .setattr    = pitix_setattr,
    .getattr    = pitix_getattr,
};

struct address_space_operations pitix_aops = {
    .readpage       = simple_readpage,
    .write_begin    = simple_write_begin,
    .write_end      = simple_write_end,
};

struct inode *pitix_iget(struct super_block *s, unsigned long ino){
    struct pitix_inode *mi;
    struct buffer_head *bh;
    struct inode *inode = new_inode(s);
    struct pitix_inode_info *pii;
    struct pitix_sb_info *sbi = (struct pitix_sb_info *)s->s_fs_info;
    long iblock;
    int a;

    inode = iget_locked(s, ino);
    if (inode == NULL)
        return ERR_PTR(-ENOMEM);
    if (!(inode->i_state & I_NEW))
        return inode;

    // pr_emerg("after if (!(inode->i_state & I_NEW))\n");

    iblock = sbi->izone_block +
        ino / pitix_inodes_per_block(s);

    /* Read disk inode block. */
    bh = sb_bread(s, iblock);
    if (bh == NULL) {
        // pr_emerg("pitix_iget: bh is new\n");
        goto out_bad_sb;
    }

    /* Extract disk inode. */
    mi = (struct pitix_inode *)(bh->b_data +
        inode_size() * (ino % pitix_inodes_per_block(s)));

    /* Fill VFS inode. */
    inode->i_mode = mi->mode;
    i_uid_write(inode, mi->uid);
    i_gid_write(inode, mi->gid);
    inode->i_size = mi->size;
    inode->i_blocks = 0;
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_kernel_time();
    inode->i_mapping->a_ops = &pitix_aops;

    if (S_ISDIR(inode->i_mode)) {
        inode->i_op = &pitix_dir_inode_operations;
        inode->i_fop = &pitix_dir_operations;

        /* Directory inodes start off with i_nlink == 2. */
        inc_nlink(inode);
    }
    if (S_ISREG(inode->i_mode)) {
        inode->i_op = &pitix_file_inode_operations;
        inode->i_fop = &pitix_file_operations;
    }

    /* Fill data for mii. */
    pii = container_of(inode, struct pitix_inode_info, vfs_inode);
    for(a = 0 ; a < INODE_DIRECT_DATA_BLOCKS ; a++)
        pii->direct_data_blocks[a] = mi->direct_data_blocks[a];
    pii->indirect_data_block = mi->indirect_data_block;

    /* Free resources. */
    brelse(bh);
    unlock_new_inode(inode);
    // pr_emerg("pitix_iget: unlock_new_inode(inode);\n");

    return inode;

out_bad_sb:
    iget_failed(inode);
    return NULL;
}

//// end inode stuff

//// start super block stuff

struct super_operations pitix_sops = {
    .statfs     = simple_statfs,
    .alloc_inode    = pitix_new_inode,
    .destroy_inode  = pitix_evict_inode,
    .write_inode    = pitix_write_inode,
    .put_super  = pitix_put_super,
};

int pitix_fill_super(struct super_block *s, void *data, int silent)
{
    int ret = -EINVAL, block_dim;
    struct pitix_sb_info *sbi;
    struct buffer_head *bh;
    struct pitix_super_block *ps;
    struct inode *root_inode;
    struct dentry *root_dentry;

    // pr_info("Fill start !");

    sbi = kzalloc(sizeof(struct pitix_sb_info), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;
    s->s_fs_info = sbi;
    mutex_init(&sbi->pitix_lock);

    if (!sb_set_blocksize(s, 4096))
        goto out_bad_blocksize;

    bh = sb_bread(s, PITIX_SUPER_BLOCK);
    if (bh == NULL)
        goto out_bad_sb;

    ps = (struct pitix_super_block *) bh->b_data;

    switch (ps->block_size_bits) {
    case 9:
        block_dim = 512;
        break;
    case 10:
        block_dim = 1024;
        break;
    case 11:
        block_dim = 2048;
        break;
    case 12:
        block_dim = 4096;
        break;
    default:
        return -1;
    }

    if (!sb_set_blocksize(s, block_dim))
        goto out_bad_blocksize;

    if (ps->magic == PITIX_MAGIC) {
        sbi->version = ps->version;
        sbi->imap_block = ps->imap_block;
        sbi->dmap_block = ps->dmap_block;
        sbi->izone_block = ps->izone_block;
        sbi->dzone_block = ps->dzone_block;
        sbi->bfree = ps->bfree;
        sbi->ffree = ps->ffree;

    } else
        goto out_bad_magic;

    s->s_magic = PITIX_MAGIC;
    s->s_op = &pitix_sops;

    /* Allocate root inode and root dentry. */
    root_inode = pitix_iget(s, 0);
    if (!root_inode)
        goto out_bad_inode;

    root_dentry = d_make_root(root_inode);
    if (!root_dentry)
        goto out_iput;
    s->s_root = root_dentry;


    /* Store superblock buffer_head for further use. */
    sbi->sb_bh = bh;

    sbi->dmap_bh = sb_bread(s,  sbi->dmap_block);

    sbi->imap_bh = sb_bread(s,  sbi->imap_block);

    // pr_info("Succ fill super !\n");


    return 0;

out_iput:
    iput(root_inode);
out_bad_inode:
    // pr_info(  "bad inode\n");
out_bad_magic:
    // pr_info(  "bad magic number\n");
    brelse(bh);
out_bad_sb:
    // pr_info(  "error reading buffer_head\n");
out_bad_blocksize:
    // pr_info(  "bad block size\n");
    s->s_fs_info = NULL;
    kfree(sbi);
    mutex_destroy(&sbi->pitix_lock);

    // pr_info("err output super");

    return ret;
}

static struct dentry *pitix_mount(struct file_system_type *fs_type,
        int flags, const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, pitix_fill_super);
}

static struct file_system_type pitix_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "pitix",
    .mount      = pitix_mount,
    .kill_sb    = kill_block_super,
    .fs_flags   = FS_REQUIRES_DEV,
};

//// end super block stuff

static int __init pitix_init (void)
{
    int err;

    err = register_filesystem(&pitix_fs_type);
    if (err) {
        // printk(LOG_LEVEL "register_filesystem failed\n");
        return err;
    }

    // pr_info("registered");

    // dprintk("registered filesystem\n");

    return 0;
}

static void pitix_exit (void)
{
    unregister_filesystem(&pitix_fs_type);
    // dprintk("unregistered filesystem\n");
}


module_init(pitix_init);
module_exit(pitix_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kmu");
