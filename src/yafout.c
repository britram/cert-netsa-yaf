/**
 ** yafout.c
 ** YAF IPFIX file and session output support
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2016 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 */

#define _YAF_SOURCE_
#include "yafout.h"
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <airframe/airutil.h>

fBuf_t *yfOutputOpen(
    yfConfig_t      *cfg,
    AirLock         *lock,
    GError          **err)
{
    GString         *namebuf = NULL;
    fBuf_t          *fbuf = NULL;
    static uint32_t serial = 0;

    /* Short-circuit IPFIX output over the wire.
       Get a writer for the given connection specifier. */
    if (cfg->ipfixNetTrans) {
#ifdef HAVE_SPREAD
        if (cfg->ipfixSpreadTrans){
            return yfWriterForSpread( &(cfg->spreadparams), cfg->odid,
                                      cfg->spreadGroupIndex,
                                      cfg->tmpl_metadata, err);
        }
#endif
        return yfWriterForSpec(&(cfg->connspec), cfg->odid, cfg->tmpl_metadata,
                               err);
    }

    /* create a buffer for the output filename */
    namebuf = g_string_new("");

    if (cfg->rotate_ms) {
        /* Output file rotation.
           Generate a filename by adding a timestamp and serial number
           to the end of the output specifier. */
        g_string_append_printf(namebuf, "%s-", cfg->outspec);
        air_time_g_string_append(namebuf, time(NULL), AIR_TIME_SQUISHED);
        g_string_append_printf(namebuf, "-%05u.yaf", serial++);
    } else {
        /* No output file rotation. Write to the file named by the output
           specifier. */
        g_string_append_printf(namebuf, "%s", cfg->outspec);
    }

    /* lock, but not stdout */
    if (lock) {
        if (!(((strlen(cfg->outspec) == 1) && cfg->outspec[0] != '-'))) {
            if (!air_lock_acquire(lock, namebuf->str, err)) {
                goto err;
            }
        }
    }
    /* start a writer on the file */

    if (!(fbuf = yfWriterForFile(namebuf->str, cfg->odid, cfg->tmpl_metadata, err))) {
        goto err;
    }

    /* all done */
    goto end;

  err:
    if (lock) {
        air_lock_release(lock);
    }

  end:
    g_string_free(namebuf, TRUE);
    return fbuf;
}

void yfOutputClose(
    fBuf_t                  *fbuf,
    AirLock                 *lock,
    gboolean                flush)
{
    gboolean                rv;
    GError                  *err = NULL;

    /* Close writer (this frees the buffer) */
    rv = yfWriterClose(fbuf, flush, &err);

    if (!rv) {
        g_critical("Error: %s", err->message);
    }

    /* Release lock */
    if (lock) {
        air_lock_release(lock);
    }
}
