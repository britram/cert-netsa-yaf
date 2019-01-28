/*
 *
 ** @file ipfixDumpPrint.h
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2015 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso <netsa-help@cert.org>
 ** ------------------------------------------------------------------------
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
 ** ------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <ctype.h>

#include <time.h>
#include <fixbuf/public.h>


typedef struct tmplContext_st {
    uint32_t           count;
    uint16_t           len;
    uint16_t           tid;
} tmplContext_t;


void idPrintHeader(
    FILE              *outfile,
    fBuf_t            *fbuf);

uint16_t idPrintTemplate(
    FILE              *fp,
    fbTemplate_t      *tmpl,
    void              **ctx,
    uint16_t          tid,
    gboolean          noprint);

void idPrintDataRecord(
    FILE         *fp,
    fbTemplate_t *tmpl,
    uint8_t      *buffer,
    size_t       buf_len,
    int          rec_count,
    char         *str_prefix);
