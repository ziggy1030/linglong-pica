/*
 * SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

package apt

import (
	"strings"

	"pkg.deepin.com/linglong/pica/cmd/ll-pica/core/comm"
)

func apt_url(appid string) (string, bool) {
	if ret, _, err := comm.ExecAndWait(10, "apt", "download", appid, "-y", "--print-uris"); err == nil {
		url := strings.Split(ret, " ")[0]
		url = strings.Replace(url, "'", "", 2)
		return url, true
	}
	return "", false
}
