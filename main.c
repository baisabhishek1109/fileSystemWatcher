#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include "fsevents.h"
#include <pwd.h>
#include <grp.h>
#include <signal.h>

#define PROGNAME "fslogger"
#define PROGVERS "2.1"

#define DEV_FSEVENTS     "/dev/fsevents" // the fsevents pseudo-device
#define FSEVENT_BUFSIZ   131072          // buffer for reading from the device
#define EVENT_QUEUE_SIZE 4096            // limited by MAX_KFS_EVENTS


static volatile int keepRunning = 1;
FILE *fptr;
void intHandler(int dummy) {
    keepRunning = 0;
    printf("keyboard interrupt");
 //   fprintf(fptr,"%s","},");
 //   fprintf(fptr,"%s","{}");
 //   fprintf(fptr,"%s","]");
}

// an event argument
typedef struct kfs_event_arg {
    u_int16_t  type;         // argument type
    u_int16_t  len;          // size of argument data that follows this field
    union {
        struct vnode *vp;
        char         *str;
        void         *ptr;
        int32_t       int32;
        dev_t         dev;
        ino_t         ino;
        int32_t       mode;
        uid_t         uid;
        gid_t         gid;
        uint64_t      timestamp;
    } data;
} kfs_event_arg_t;

#define KFS_NUM_ARGS  FSE_MAX_ARGS

// an event
typedef struct kfs_event {
    int32_t         type; // event type
    pid_t           pid;  // pid of the process that performed the operation
    kfs_event_arg_t args[KFS_NUM_ARGS]; // event arguments
} kfs_event;

// event names
static const char *kfseNames[] = {
    "FSE_CREATE_FILE",
    "FSE_DELETE",
    "FSE_STAT_CHANGED",
    "FSE_RENAME",
    "FSE_CONTENT_MODIFIED",
    "FSE_EXCHANGE",
    "FSE_FINDER_INFO_CHANGED",
    "FSE_CREATE_DIR",
    "FSE_CHOWN",
    "FSE_XATTR_MODIFIED",
    "FSE_XATTR_REMOVED",
};

// argument names
static const char *kfseArgNames[] = {
    "FSE_ARG_UNKNOWN", "FSE_ARG_VNODE", "FSE_ARG_STRING", "FSE_ARGPATH",
    "FSE_ARG_INT32",   "FSE_ARG_INT64", "FSE_ARG_RAW",    "FSE_ARG_INO",
    "FSE_ARG_UID",     "FSE_ARG_DEV",   "FSE_ARG_MODE",   "FSE_ARG_GID",
    "FSE_ARG_FINFO",
};

// for pretty-printing of vnode types
enum vtype {
    VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR, VCPLX
};

enum vtype iftovt_tab[] = {
    VNON, VFIFO, VCHR, VNON, VDIR,  VNON, VBLK, VNON,
    VREG, VNON,  VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};

static const char *vtypeNames[] = {
    "VNON",  "VREG",  "VDIR", "VBLK", "VCHR", "VLNK",
    "VSOCK", "VFIFO", "VBAD", "VSTR", "VCPLX",
};
#define VTYPE_MAX (sizeof(vtypeNames)/sizeof(char *))

static char *
get_proc_name(pid_t pid)
{
    size_t        len = sizeof(struct kinfo_proc);
    static int    name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    static struct kinfo_proc kp;
    
    name[3] = pid;
    
    kp.kp_proc.p_comm[0] = '\0';
    if (sysctl((int *)name, sizeof(name)/sizeof(*name), &kp, &len, NULL, 0))
        return "?";
    
    if (kp.kp_proc.p_comm[0] == '\0')
        return "exited?";
    
    return kp.kp_proc.p_comm;
}

int
main(int argc, char **argv)
{
    
 /*   char str[80];
    strcpy (str,"these ");
    strcat (str,"strings ");
    strcat (str,"are ");
    strcat (str,"concatenated.");
    puts (str); */
    
    
    char path[10];
    char usrname[50];
    char* uname = argv[1];
  //  path = "/Users/";
    strcpy(path,"/Users/");
    strcpy(usrname,uname);
    char finalpath[150];
    strcpy(finalpath,path);
    strcat(finalpath, usrname);
    strcat(finalpath, "/Desktop/test.json");
  
    
    //"/Users/abhsing/Desktop/test.json"
    fptr = fopen(finalpath, "w");
    fprintf(fptr,"%s","[");
    int32_t arg_id;
    int     fd, clonefd = -1;
    int     i, j, eoff, off, ret;
    
    kfs_event_arg_t *kea;
    struct           fsevent_clone_args fca;
    char             buffer[FSEVENT_BUFSIZ];
    struct passwd   *p;
    struct group    *g;
    mode_t           va_mode;
    u_int32_t        va_type;
    u_int32_t        is_fse_arg_vnode = 0;
    char             fileModeString[11 + 1];
    int8_t           event_list[] = { // action to take for each event
        FSE_REPORT,  // FSE_CREATE_FILE,
        FSE_REPORT,  // FSE_DELETE,
        FSE_REPORT,  // FSE_STAT_CHANGED,
        FSE_REPORT,  // FSE_RENAME,
        FSE_REPORT,  // FSE_CONTENT_MODIFIED,
        FSE_REPORT,  // FSE_EXCHANGE,
        FSE_REPORT,  // FSE_FINDER_INFO_CHANGED,
        FSE_REPORT,  // FSE_CREATE_DIR,
        FSE_REPORT,  // FSE_CHOWN,
        FSE_REPORT,  // FSE_XATTR_MODIFIED,
        FSE_REPORT,  // FSE_XATTR_REMOVED,
    };
    
    /*if (argc != 1) {
        exit(1);
    } */
    
    if (geteuid() != 0) {
        fprintf(stderr, "You must be root to run %s. Try again using 'sudo'.\n",
                PROGNAME);
        exit(1);
    }
    
    setbuf(stdout, NULL);
    
    if ((fd = open(DEV_FSEVENTS, O_RDONLY)) < 0) {
        perror("open");
        exit(1);
    }
    
    fca.event_list = (int8_t *)event_list;
    fca.num_events = sizeof(event_list)/sizeof(int8_t);
    fca.event_queue_depth = EVENT_QUEUE_SIZE;
    fca.fd = &clonefd;
    if ((ret = ioctl(fd, FSEVENTS_CLONE, (char *)&fca)) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }
    
    close(fd);
    printf("fsevents device cloned (fd %d)\nfslogger ready\n", clonefd);
    
    if ((ret = ioctl(clonefd, FSEVENTS_WANT_EXTENDED_INFO, NULL)) < 0) {
        perror("ioctl");
        close(clonefd);
        exit(1);
    }
    
    signal(SIGINT, intHandler);
    
    while (keepRunning) { // event processing loop
        
        if ((ret = read(clonefd, buffer, FSEVENT_BUFSIZ)) > 0)
            printf("=> received %d bytes\n", ret);
        
        off = 0;
        
        while (off < ret) { // process one or more events received
            fprintf(fptr,"%s","{");
            struct kfs_event *kfse = (struct kfs_event *)((char *)buffer + off);
            
            off += sizeof(int32_t) + sizeof(pid_t); // type + pid
            
            if (kfse->type == FSE_EVENTS_DROPPED) { // special event
                printf("# Event\n");
                fprintf(fptr,"  \"%-14s\" : \"%s\",", "type", "EVENTS DROPPED");
                fprintf(fptr,"  \"%-14s\" : \"%d\",", "pid", kfse->pid);
                off += sizeof(u_int16_t); // FSE_ARG_DONE: sizeof(type)
                fprintf(fptr,"\"%s\" : \"%s\" %s","1","1","},");
                continue;
            }
            
            int32_t atype = kfse->type & FSE_TYPE_MASK;
            uint32_t aflags = FSE_GET_FLAGS(kfse->type);
            
            if ((atype < FSE_MAX_EVENTS) && (atype >= -1)) {
                printf("# Event\n");
                fprintf(fptr,"  \"%-14s\" : \"%s\",", "type", kfseNames[atype]);
                if (aflags & FSE_COMBINED_EVENTS) {
                    printf("%s", ", combined events");
                }
                if (aflags & FSE_CONTAINS_DROPPED_EVENTS) {
                    printf("%s", ", contains dropped events");
                }
                printf("\n");
            } else { // should never happen
              //  printf("This may be a program bug (type = %d).\n", atype);
              //  exit(1);
               // fprintf(fptr,"%s","]");
                fclose(fptr);
                printf("tried to turn off");
             //   fptr = fopen("/Users/abhsing/Desktop/test.json", "a+");
            }
            
            fprintf(fptr,"  \"%-14s\" : \"%d (%s)\",", "pid", kfse->pid,
                   get_proc_name(kfse->pid));
            printf("  # Details\n    # %-14s%4s  %s\n", "type", "len", "data");
            
            kea = kfse->args;
            i = 0;
            
            //while ((off < ret) && (i <= FSE_MAX_ARGS)) { // process arguments
            while (off < ret) {
                
                i++;
                
                if (kea->type == FSE_ARG_DONE) { // no more arguments
                    printf("    \"%s\" : \"(%#x)\"", "FSE_ARG_DONE", kea->type);
                    off += sizeof(u_int16_t);
                    break;
                }
                
                eoff = sizeof(kea->type) + sizeof(kea->len) + kea->len;
                off += eoff;
                
                arg_id = (kea->type > FSE_MAX_ARGS) ? 0 : kea->type;
                printf("    %-16s : %4hd , ", kfseArgNames[arg_id], kea->len);
                
                switch (kea->type) { // handle based on argument type
                        
                    case FSE_ARG_VNODE:  // a vnode (string) pointer
                        is_fse_arg_vnode = 1;
                        printf("%-6s : %s,", "path", (char *)&(kea->data.vp));
                        break;
                        
                    case FSE_ARG_STRING: // a string pointer
                        fprintf(fptr,"\"%-6s\" : \"%s\",", "string", (char *)&(kea->data.str));
                        break;
                        
                    case FSE_ARG_INT32:
                        printf("%-6s : %d,", "int32", kea->data.int32);
                        break;
                        
                    case FSE_ARG_RAW: // a void pointer
                        printf("%-6s : ", "ptr");
                        for (j = 0; j < kea->len; j++)
                            printf("%02x", ((char *)kea->data.ptr)[j]);
                        printf("\n");
                        break;
                        
                    case FSE_ARG_INO: // an inode number
                        printf("%-6s : %d,", "ino", kea->data.ino);
                        break;
                        
                    case FSE_ARG_UID: // a user ID
                        p = getpwuid(kea->data.uid);
                        printf("%-6s : %d (%s),", "uid", kea->data.uid,
                               (p) ? p->pw_name : "?");
                        break;
                        
                    case FSE_ARG_DEV: // a file system ID or a device number
                        if (is_fse_arg_vnode) {
                            printf("%-6s : %#08x,", "fsid", kea->data.dev);
                            is_fse_arg_vnode = 0;
                        } else {
                            printf("%-6s : %#08x (major %u, minor %u)",
                                   "dev", kea->data.dev,
                                   major(kea->data.dev), minor(kea->data.dev));
                        }
                        break;
                        
                    case FSE_ARG_MODE: // a combination of file mode and file type
                        va_mode = (kea->data.mode & 0x0000ffff);
                        va_type = (kea->data.mode & 0xfffff000);
                        strmode(va_mode, fileModeString);
                        va_type = iftovt_tab[(va_type & S_IFMT) >> 12];
                        printf("%-6s = %s (%#08x, vnode type %s)", "mode",
                               fileModeString, kea->data.mode,
                               (va_type < VTYPE_MAX) ?  vtypeNames[va_type] : "?");
                        if (kea->data.mode & FSE_MODE_HLINK) {
                            printf("%s", ", hard link");
                        }
                        if (kea->data.mode & FSE_MODE_LAST_HLINK) {
                            printf("%s", ", link count zero now");
                        }
                        printf("\n");
                        break;
                        
                    case FSE_ARG_GID: // a group ID
                        g = getgrgid(kea->data.gid);
                        printf("%-6s = %d (%s)\n", "gid", kea->data.gid,
                               (g) ? g->gr_name : "?");
                        break;
                        
                    case FSE_ARG_INT64: // timestamp
                        printf("%-6s = %llu\n", "tstamp", kea->data.timestamp);
                        break;
                        
                    default:
                        printf("%-6s = ?\n", "unknown");
                        break;
                }
                
                kea = (kfs_event_arg_t *)((char *)kea + eoff); // next
            } // for each argument
            fprintf(fptr," \"%s\" : \"%s\" %s","1","1","},");
        } // for each event
    } // forever
    fprintf(fptr,"%s","{}");
    fprintf(fptr,"%s","]");
    fclose(fptr);
    close(clonefd);
    
    exit(0);
}
