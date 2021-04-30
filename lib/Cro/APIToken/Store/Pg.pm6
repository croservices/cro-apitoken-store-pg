use Cro::APIToken::Store;
use DB::Pg;
use JSON::Fast;

class Cro::APIToken::Store::Pg does Cro::APIToken::Store {
    has Str $.table-name = 'croapitokenstorepg';
    has Bool $.create-table = True;
    has DB::Pg:D $.handle is required;

    method create-token(Str $token, DateTime $expiration, %metadata --> Nil) {
        return unless self!check-db-table-presence();
        $!handle.query("INSERT INTO $!table-name (token, expiration, metadata, revoked) VALUES (\$1, \$2, \$3, \$4)",
                $token, $expiration, %metadata, False);
    }

    method resolve-token(Cro::APIToken::Manager $manager, Str $token --> Cro::APIToken::Token) {
        return Cro::APIToken::Token unless self!check-db-table-presence();
        my $res = $!handle.query("SELECT * FROM $!table-name WHERE token = \$1", $token).hash;
        with $res {
            Cro::APIToken::Token.new(:$manager, |$_);
        } else {
            return Cro::APIToken::Token;
        }
    }

    method find-tokens(Cro::APIToken::Manager $manager, :%metadata,
                       Bool :$expired = False, Bool :$revoked --> Seq) {
        return ().Seq unless self!check-db-table-presence();
        my $ordered-values = %metadata.keys.cache;
        my $metadata-format = $ordered-values.kv.map(-> $k, $v { "(metadata->>'$v') = \${ $k + 1 }" }).join(' AND ');
        $metadata-format = 'AND ' ~ $metadata-format if $metadata-format;

        my $query-text = "SELECT * FROM $!table-name WHERE { $expired ?? 'true' !! 'expiration > now()::date' } { $revoked ?? 'AND true' !! 'AND revoked = FALSE' } " ~
                $metadata-format ~ ';';
        my $rows = $!handle.query($query-text, |$ordered-values.map({ %metadata{$_} })).hashes;
        $rows.map({ Cro::APIToken::Token.new(:$manager, |$_) });
    }

    method revoke(Str $token --> Nil) {
        return unless self!check-db-table-presence();
        $!handle.query("UPDATE $!table-name SET revoked = TRUE WHERE token = \$1;", $token);
    }

    method !check-db-table-presence() {
        my $table-exists = $!handle.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'croapitokenstorepg');").value;
        if !$table-exists && $!create-table {
            $!handle.execute('CREATE TEMPORARY table CroAPITokenStorePg (id serial NOT NULL PRIMARY KEY, token text NOT NULL, expiration timestamp NOT NULL, metadata json, revoked boolean);');
            return True;
        }
        $table-exists;
    }
}
