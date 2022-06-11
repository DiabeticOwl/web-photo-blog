package photo

import (
	"fmt"
	"web-photo-blog/config"

	"web-photo-blog/user"

	_ "github.com/lib/pq"
)

type Photo struct {
	UserId    int
	PhotoBlob []byte
	Fname     string
}

func SearchPhoto(fname string) (Photo, error) {
	var p Photo

	db := config.Connect()
	defer db.Close()

	q := fmt.Sprintf(`
		SELECT
			user_id,
			photo_blob,
			filename
		FROM photos
		WHERE
			filename = $1;
	`)
	row := db.QueryRow(q, fname)

	err := row.Scan(
		&p.UserId,
		&p.PhotoBlob,
		&p.Fname,
	)
	return p, err
}

func AddPhoto(u user.User, f []byte, fname string) error {
	db := config.Connect()
	defer db.Close()

	q := fmt.Sprintf(`
		INSERT INTO photos (
			user_id,
			photo_blob,
			filename
		)
		VALUES (
			$1,
			$2,
			$3
		);
	`)
	_, err := db.Exec(
		q,
		u.ID, f, fname,
	)

	return err
}
