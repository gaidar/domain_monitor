package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"html/template"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/domainr/whois"
	"golang.org/x/net/publicsuffix"
)

type Domain struct {
	ID           uint   `gorm:"primaryKey"`
	Name         string `gorm:"uniqueIndex"`
	CertExpiry   time.Time
	DomainExpiry time.Time
	LastCheck    time.Time
}

func daysLeft(expiry time.Time) int {
	return int(time.Until(expiry).Hours() / 24)
}

func checkExpiry(domain string) (certExpiry, domainExpiry time.Time, err error) {
	// Check certificate expiry
	certExpiry, err = getCertExpiry(domain)
	if err != nil {
		return
	}

	// Check domain expiry using WHOIS
	domainExpiry, err = getDomainExpiry(domain)
	return
}

func getCertExpiry(domain string) (time.Time, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to connect via TLS: %v", err)
	}
	defer conn.Close()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		if cert.IsCA {
			continue // Skip CA certificates
		}
		return cert.NotAfter, nil
	}

	return time.Time{}, fmt.Errorf("no valid certificate found")
}

func getDomainExpiry(domain string) (time.Time, error) {
	eTLD, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse domain: %v", err)
	}

	req, err := whois.NewRequest(eTLD)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create WHOIS request: %v", err)
	}

	resp, err := whois.DefaultClient.Fetch(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("WHOIS request failed: %v", err)
	}

	return parseWhoisExpiry(resp.String())
}

func parseWhoisExpiry(whoisData string) (time.Time, error) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05-0700",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
	}

	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "expiry date") ||
			strings.Contains(strings.ToLower(line), "expiration date") ||
			strings.Contains(strings.ToLower(line), "expires on") ||
			strings.Contains(strings.ToLower(line), "registrar registration expiration date") {

			fields := strings.SplitN(line, ":", 2)
			if len(fields) != 2 {
				continue
			}

			dateStr := strings.TrimSpace(fields[1])
			for _, layout := range layouts {
				if expiryDate, err := time.Parse(layout, dateStr); err == nil {
					return expiryDate, nil
				}
			}
		}
	}

	return time.Time{}, fmt.Errorf("expiry date not found in WHOIS data")
}

func refreshDomain(db *gorm.DB, d *Domain) {
	certExpiry, domainExpiry, err := checkExpiry(d.Name)
	if err == nil {
		db.Model(d).Updates(Domain{
			CertExpiry:   certExpiry,
			DomainExpiry: domainExpiry,
			LastCheck:    time.Now(),
		})
	}
}

func main() {
	godotenv.Load()

	db, err := gorm.Open(sqlite.Open(os.Getenv("DB_DSN")), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&Domain{})

	r := gin.Default()

	r.SetFuncMap(template.FuncMap{
		"daysLeft": daysLeft,
	})

	r.LoadHTMLGlob("templates/*.tmpl")
	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		var domains []Domain
		db.Order("name asc").Find(&domains)
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"domains": domains,
		})
	})

	r.POST("/domains", func(c *gin.Context) {
		names := strings.Split(c.PostForm("names"), "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			var domain Domain
			if err := db.FirstOrCreate(&domain, Domain{Name: name}).Error; err != nil {
				log.Println("Error creating domain:", err)
			} else {
				refreshDomain(db, &domain) // refresh immediately after add
			}
		}
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.POST("/domains/:id/delete", func(c *gin.Context) {
		db.Delete(&Domain{}, c.Param("id"))
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.POST("/refresh", func(c *gin.Context) {
		var domains []Domain
		db.Find(&domains)
		for _, d := range domains {
			refreshDomain(db, &d)
		}
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.Run(":8080")
}
